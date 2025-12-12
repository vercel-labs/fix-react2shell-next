const fs = require('fs');
const path = require('path');

const { c } = require('./utils/colors');
const { parseVersion, compareVersions, isUnparseableVersionSpec, hasRangeSpecifier } = require('./utils/version');
const { findAllPackageJsons, findProjectRoot, findMonorepoRoot } = require('./utils/filesystem');
const { detectPackageManager, getInstalledVersion, runInstall } = require('./utils/package-manager');
const { vulnerabilities, getAllPackages } = require('./vulnerabilities');

/**
 * Analyze a package.json file for vulnerabilities across all CVEs
 */
function analyzePackageJson(pkgPath) {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    return null;
  }

  const pkgDir = path.dirname(pkgPath);
  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
  const packagesToCheck = getAllPackages();

  const vulnerablePackages = [];

  for (const packageName of packagesToCheck) {
    if (!allDeps[packageName]) continue;

    let version = allDeps[packageName];
    let installedVersion = null;
    let displayVersion = version;
    let shouldCheckInstalled = isUnparseableVersionSpec(version) || !parseVersion(version) || hasRangeSpecifier(version);

    if (shouldCheckInstalled) {
      installedVersion = getInstalledVersion(pkgDir, packageName);
      if (installedVersion) {
        displayVersion = `${version} (installed: ${installedVersion})`;
        version = installedVersion;
      }
    }

    // Check against all vulnerability modules
    const affectedCves = [];
    for (const vuln of vulnerabilities) {
      if (!vuln.packages.includes(packageName)) continue;

      const check = vuln.isVulnerable(packageName, version);
      if (check.vulnerable) {
        const patch = vuln.getPatchedVersion(packageName, version);
        affectedCves.push({
          id: vuln.id,
          severity: vuln.severity,
          patchedVersion: patch?.recommended || null,
          alternative: patch?.alternative || null,
          note: patch?.note || null,
        });
      }
    }

    // Handle unparseable version with no installed version found
    if (affectedCves.length === 0 && isUnparseableVersionSpec(allDeps[packageName]) && !installedVersion) {
      vulnerablePackages.push({
        package: packageName,
        current: allDeps[packageName],
        cves: [{ id: 'UNKNOWN', severity: 'unknown', patchedVersion: '15.5.8' }],
        patched: '15.5.8',
        note: 'Could not determine installed version - run "npm install" first, or pin to a safe version',
        inDeps: !!pkg.dependencies?.[packageName],
        inDevDeps: !!pkg.devDependencies?.[packageName],
      });
      continue;
    }

    if (affectedCves.length > 0) {
      vulnerablePackages.push({
        package: packageName,
        current: displayVersion,
        cves: affectedCves,
        inDeps: !!pkg.dependencies?.[packageName],
        inDevDeps: !!pkg.devDependencies?.[packageName],
      });
    }
  }

  return {
    path: pkgPath,
    name: pkg.name || path.basename(path.dirname(pkgPath)),
    vulnerabilities: vulnerablePackages,
  };
}

/**
 * Compute the minimal set of version changes needed to fix all vulnerabilities
 * For each package, find the highest required version across all CVEs
 */
function computeMinimalFixes(analysisResults) {
  const fixes = [];

  for (const file of analysisResults) {
    const fileFixes = [];

    for (const vuln of file.vulnerabilities) {
      // Find the highest patched version required across all CVEs
      let highestVersion = null;
      let notes = [];
      let alternatives = [];

      for (const cve of vuln.cves) {
        if (cve.patchedVersion) {
          if (!highestVersion || compareVersions(cve.patchedVersion, highestVersion) > 0) {
            highestVersion = cve.patchedVersion;
          }
        }
        if (cve.note) notes.push(cve.note);
        if (cve.alternative) alternatives.push(cve.alternative);
      }

      fileFixes.push({
        package: vuln.package,
        current: vuln.current,
        patched: highestVersion,
        cves: vuln.cves.map(c => c.id),
        note: notes.length > 0 ? notes[0] : null, // Use first note
        alternative: alternatives.length > 0 ? alternatives[0] : null,
        inDeps: vuln.inDeps,
        inDevDeps: vuln.inDevDeps,
      });
    }

    if (fileFixes.length > 0) {
      fixes.push({
        path: file.path,
        name: file.name,
        fixes: fileFixes,
      });
    }
  }

  return fixes;
}

/**
 * Apply fixes to a package.json file
 */
function applyFixes(pkgPath, fixes) {
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  let modified = false;

  for (const fix of fixes) {
    if (!fix.patched) continue;

    // Pin exact version
    const newVersion = fix.patched;

    if (fix.inDeps && pkg.dependencies?.[fix.package]) {
      pkg.dependencies[fix.package] = newVersion;
      modified = true;
    }
    if (fix.inDevDeps && pkg.devDependencies?.[fix.package]) {
      pkg.devDependencies[fix.package] = newVersion;
      modified = true;
    }
  }

  if (modified) {
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  }

  return modified;
}

/**
 * Format CVE IDs for display
 */
function formatCves(cves) {
  if (cves.length === 0) return '';
  return ` [${cves.join(', ')}]`;
}

/**
 * Main CLI runner
 */
async function run() {
  const cwd = process.cwd();
  const args = process.argv.slice(2);
  const shouldFix = args.includes('--fix') || args.includes('-f');
  const dryRun = args.includes('--dry-run') || args.includes('-d');
  const jsonOutput = args.includes('--json');
  const lockfileOnly = args.includes('--lockfile-only');

  if (!jsonOutput) {
    console.log('\n' + c('bold', 'fix-react2shell-next') + c('dim', ' - Next.js vulnerability scanner\n'));
    console.log(c('dim', `Checking for ${vulnerabilities.length} known vulnerabilities:\n`));
    for (const vuln of vulnerabilities) {
      const severityColor = vuln.severity === 'critical' ? 'red' : vuln.severity === 'high' ? 'yellow' : 'cyan';
      console.log(c('dim', '  - ') + c(severityColor, vuln.id) + c('dim', ` (${vuln.severity}): ${vuln.description}`));
    }
    console.log();
  }

  const packageJsonPaths = findAllPackageJsons(cwd);

  if (packageJsonPaths.length === 0) {
    if (jsonOutput) {
      console.log(JSON.stringify({ vulnerable: false, reason: 'no-package-json' }));
    } else {
      console.log(c('yellow', 'No package.json files found in current directory.\n'));
    }
    return;
  }

  if (!jsonOutput) {
    console.log(c('dim', `Found ${packageJsonPaths.length} package.json file(s)\n`));
  }

  const allAnalysis = [];

  for (const pkgPath of packageJsonPaths) {
    const analysis = analyzePackageJson(pkgPath);
    if (analysis && analysis.vulnerabilities.length > 0) {
      allAnalysis.push(analysis);
    }
  }

  // Compute minimal fixes
  const minimalFixes = computeMinimalFixes(allAnalysis);

  if (jsonOutput) {
    console.log(JSON.stringify({
      vulnerable: minimalFixes.length > 0,
      count: minimalFixes.length,
      files: minimalFixes,
    }, null, 2));
    return;
  }

  if (minimalFixes.length === 0) {
    console.log(c('green', 'No vulnerable packages found!'));
    console.log(c('dim', '  Your project is not affected by any known vulnerabilities.\n'));
    return;
  }

  console.log(c('red', `Found ${minimalFixes.length} vulnerable file(s):\n`));

  for (const file of minimalFixes) {
    const relativePath = path.relative(cwd, file.path) || 'package.json';
    console.log(c('yellow', `  ${relativePath}`));

    for (const fix of file.fixes) {
      const cveList = formatCves(fix.cves);
      console.log(c('dim', `     ${fix.package}: `) + c('red', fix.current) + c('dim', ' -> ') + c('green', fix.patched || '?') + c('magenta', cveList));
      if (fix.note) {
        console.log(c('dim', `        ${fix.note}`));
      }
    }
    console.log();
  }

  if (dryRun) {
    console.log(c('cyan', 'Dry run - no changes made.'));
    console.log(c('dim', '   Run with --fix to apply patches.\n'));
    return;
  }

  if (!shouldFix) {
    const isInteractive = process.stdin.isTTY;

    if (!isInteractive) {
      console.log(c('yellow', 'Running in non-interactive mode.'));
      console.log(c('dim', '   Use --fix to auto-apply patches.\n'));
      process.exit(1);
      return;
    }

    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const answer = await new Promise((resolve) => {
      rl.question(c('cyan', 'Apply fixes? [Y/n] '), resolve);
    });
    rl.close();

    const confirmed = !answer || answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';

    if (!confirmed) {
      console.log(c('yellow', '\nFix skipped. Your project remains vulnerable.\n'));
      process.exit(1);
      return;
    }
  }

  console.log(c('cyan', '\nApplying fixes...\n'));

  const modifiedDirs = [];
  for (const file of minimalFixes) {
    const relativePath = path.relative(cwd, file.path) || 'package.json';
    const modified = applyFixes(file.path, file.fixes);
    if (modified) {
      console.log(c('green', `   Updated ${relativePath}`));
      modifiedDirs.push(path.dirname(file.path));
    }
  }

  if (modifiedDirs.length === 0) {
    console.log(c('yellow', '   No files were modified (patches may require manual intervention).\n'));
    return;
  }

  console.log(c('cyan', lockfileOnly ? '\nUpdating lockfile...\n' : '\nInstalling dependencies...\n'));

  let allInstallsSucceeded = true;

  const monorepoRoot = findMonorepoRoot(cwd);

  if (monorepoRoot) {
    const packageManager = detectPackageManager(monorepoRoot);
    const relativeRoot = path.relative(cwd, monorepoRoot) || '.';
    console.log(c('dim', `Monorepo root: ${relativeRoot} (${packageManager})`));

    const installSuccess = runInstall(packageManager, monorepoRoot, { lockfileOnly });
    if (!installSuccess) {
      allInstallsSucceeded = false;
    }
  } else {
    const projectRoots = new Set();
    for (const dir of modifiedDirs) {
      const root = findProjectRoot(dir);
      projectRoots.add(root);
    }

    for (const root of projectRoots) {
      const relativeRoot = path.relative(cwd, root) || '.';
      const packageManager = detectPackageManager(root);
      console.log(c('dim', `${relativeRoot} (${packageManager})`));

      const installSuccess = runInstall(packageManager, root, { lockfileOnly });
      if (!installSuccess) {
        allInstallsSucceeded = false;
      }
    }
  }

  if (allInstallsSucceeded) {
    if (lockfileOnly) {
      console.log(c('green', '\nPatches applied and lockfile updated!'));
      console.log(c('dim', '   Run your package manager\'s install command to download the updated packages.'));
    } else {
      console.log(c('green', '\nPatches applied!'));
    }
    console.log(c('dim', '   Remember to test your app and commit the changes.\n'));
  } else {
    console.log(c('yellow', lockfileOnly ? '\nLockfile update had issues.' : '\nSome install commands had issues.'));
    console.log(c('dim', '   The package.json files have been updated.'));
    console.log(c('dim', '   Please run install commands manually in the affected directories.\n'));
  }
}

module.exports = { run, findAllPackageJsons, analyzePackageJson, computeMinimalFixes };
