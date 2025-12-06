const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
};

const c = (color, text) => `${colors[color]}${text}${colors.reset}`;

const NEXT_PATCHED_VERSIONS = {
  '15.0': '15.0.5',
  '15.1': '15.1.9',
  '15.2': '15.2.6',
  '15.3': '15.3.6',
  '15.4': '15.4.8',
  '15.5': '15.5.7',
  '16.0': '16.0.7',
};

const NEXT_CANARY_PATCHES = {
  15: '15.6.0-canary.58',
  16: '16.1.0-canary.12',
};

const NEXT_14_SAFE_VERSION = '14.2.29';
const NEXT_14_SAFE_CANARY = '14.3.0-canary.77';

const REACT_RSC_PATCHES = {
  '19.0.0': '19.0.1',
  '19.1.0': '19.1.2',
  '19.1.1': '19.1.2',
  '19.2.0': '19.2.1',
};

const REACT_RSC_PACKAGES = [
  'react-server-dom-webpack',
  'react-server-dom-parcel',
  'react-server-dom-turbopack',
];

const SKIP_DIRS = new Set([
  'node_modules',
  '.next',
  '.turbo',
  '.git',
  'dist',
  'build',
  '.output',
  '.nuxt',
  '.vercel',
  'coverage',
]);

function parseVersion(version) {
  if (!version) return null;
  
  const cleaned = version.replace(/^[\^~>=<]+/, '').trim();
  
  // Handle canary: 15.1.0-canary.42
  const canaryMatch = cleaned.match(/^(\d+)\.(\d+)\.(\d+)-canary\.(\d+)$/);
  if (canaryMatch) {
    return {
      major: parseInt(canaryMatch[1], 10),
      minor: parseInt(canaryMatch[2], 10),
      patch: parseInt(canaryMatch[3], 10),
      canary: parseInt(canaryMatch[4], 10),
      isCanary: true,
      raw: cleaned,
    };
  }
  
  // Handle RC: 15.1.0-rc.0
  const rcMatch = cleaned.match(/^(\d+)\.(\d+)\.(\d+)-rc\.(\d+)$/);
  if (rcMatch) {
    return {
      major: parseInt(rcMatch[1], 10),
      minor: parseInt(rcMatch[2], 10),
      patch: parseInt(rcMatch[3], 10),
      rc: parseInt(rcMatch[4], 10),
      isRC: true,
      raw: cleaned,
    };
  }
  
  // Handle stable: 15.1.0
  const stableMatch = cleaned.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (stableMatch) {
    return {
      major: parseInt(stableMatch[1], 10),
      minor: parseInt(stableMatch[2], 10),
      patch: parseInt(stableMatch[3], 10),
      isStable: true,
      raw: cleaned,
    };
  }
  
  return null;
}

function compareVersions(a, b) {
  const vA = typeof a === 'string' ? parseVersion(a) : a;
  const vB = typeof b === 'string' ? parseVersion(b) : b;
  
  if (!vA || !vB) return 0;
  
  if (vA.major !== vB.major) return vA.major - vB.major;
  if (vA.minor !== vB.minor) return vA.minor - vB.minor;
  if (vA.patch !== vB.patch) return vA.patch - vB.patch;
  
  // canary < rc < stable
  const getPreReleaseOrder = (v) => {
    if (v.isCanary) return 0;
    if (v.isRC) return 1;
    return 2;
  };
  
  const orderA = getPreReleaseOrder(vA);
  const orderB = getPreReleaseOrder(vB);
  
  if (orderA !== orderB) return orderA - orderB;
  
  if (vA.isCanary && vB.isCanary) return vA.canary - vB.canary;
  if (vA.isRC && vB.isRC) return vA.rc - vB.rc;
  
  return 0;
}

function isNextVersionVulnerable(version) {
  const parsed = parseVersion(version);
  if (!parsed) return { vulnerable: false, reason: 'unparseable' };
  
  const { major, minor, raw, isCanary } = parsed;
  
  // Next.js < 14.3.0-canary.77 is not affected
  if (major < 14) {
    return { vulnerable: false, reason: 'version-too-old' };
  }
  
  if (major === 14) {
    if (!isCanary) {
      // Stable 14.x is not affected
      return { vulnerable: false, reason: 'stable-14-not-affected' };
    }
    // 14.3.0-canary.77+ is vulnerable
    if (minor === 3 && parsed.canary >= 77) {
      return { vulnerable: true, reason: '14.3-canary-77+' };
    }
    return { vulnerable: false, reason: 'canary-before-77' };
  }
  
  // Next.js 15.x
  if (major === 15) {
    if (isCanary) {
      // All 15.x canaries before 15.6.0-canary.58 are vulnerable
      if (compareVersions(raw, '15.6.0-canary.58') < 0) {
        return { vulnerable: true, reason: '15.x-canary' };
      }
      return { vulnerable: false, reason: 'patched-canary' };
    }
    
    // Stable 15.x - check against patched versions
    const minorKey = `${major}.${minor}`;
    const patchedVersion = NEXT_PATCHED_VERSIONS[minorKey];
    
    if (!patchedVersion) {
      // Unknown minor, assume safe if >= 15.6
      return { vulnerable: minor < 6, reason: minor < 6 ? 'unknown-minor-assume-vulnerable' : 'unknown-minor-assume-safe' };
    }
    
    if (compareVersions(raw, patchedVersion) < 0) {
      return { vulnerable: true, reason: `below-${patchedVersion}` };
    }
    return { vulnerable: false, reason: 'patched' };
  }
  
  // Next.js 16.x
  if (major === 16) {
    if (isCanary) {
      // All 16.x canaries before 16.1.0-canary.12 are vulnerable
      if (compareVersions(raw, '16.1.0-canary.12') < 0) {
        return { vulnerable: true, reason: '16.x-canary' };
      }
      return { vulnerable: false, reason: 'patched-canary' };
    }
    
    // Stable 16.x
    const minorKey = `${major}.${minor}`;
    const patchedVersion = NEXT_PATCHED_VERSIONS[minorKey];
    
    if (patchedVersion && compareVersions(raw, patchedVersion) < 0) {
      return { vulnerable: true, reason: `below-${patchedVersion}` };
    }
    
    // 16.1+ stable is safe
    if (minor >= 1) {
      return { vulnerable: false, reason: 'patched' };
    }
    
    // 16.0.x below 16.0.7 is vulnerable
    if (minor === 0 && parsed.patch < 7) {
      return { vulnerable: true, reason: 'below-16.0.7' };
    }
    
    return { vulnerable: false, reason: 'patched' };
  }
  
  // Future versions (17+) - assume safe
  return { vulnerable: false, reason: 'future-version' };
}

function isReactRscVersionVulnerable(version) {
  const cleaned = version.replace(/^[\^~>=<]+/, '').trim();
  return REACT_RSC_PATCHES.hasOwnProperty(cleaned);
}

function getNextPatchedVersion(version) {
  const parsed = parseVersion(version);
  if (!parsed) return null;
  
  const { major, minor, isCanary } = parsed;
  
  // 14.3.0-canary.77+ special case
  if (major === 14 && isCanary) {
    return {
      recommended: NEXT_14_SAFE_CANARY,
      alternative: '15.0.5',
      note: 'Downgrade to safe canary or upgrade to 15.0.5',
    };
  }
  
  // Canary versions
  if (isCanary) {
    const canaryPatch = NEXT_CANARY_PATCHES[major];
    if (canaryPatch) {
      return { recommended: canaryPatch };
    }
  }
  
  // Stable versions
  const minorKey = `${major}.${minor}`;
  const patchedVersion = NEXT_PATCHED_VERSIONS[minorKey];
  
  if (patchedVersion) {
    return { recommended: patchedVersion };
  }
  
  // Fallback for unknown minors
  if (major === 15) return { recommended: '15.5.7' };
  if (major === 16) return { recommended: '16.0.7' };
  
  return null;
}

function getReactRscPatchedVersion(version) {
  const cleaned = version.replace(/^[\^~>=<]+/, '').trim();
  return REACT_RSC_PATCHES[cleaned] || null;
}

function getInstalledVersion(pkgDir, packageName) {
  const nodeModulesPath = path.join(pkgDir, 'node_modules', packageName, 'package.json');
  try {
    const pkg = JSON.parse(fs.readFileSync(nodeModulesPath, 'utf8'));
    return pkg.version;
  } catch (e) {
    return null;
  }
}

function isUnparseableVersionSpec(version) {
  if (!version) return true;
  const unparseable = ['latest', 'next', 'canary', '*', 'x'];
  const cleaned = version.replace(/^[\^~>=<]+/, '').trim().toLowerCase();
  return unparseable.includes(cleaned) || cleaned.startsWith('npm:') || cleaned.includes('/');
}

function findAllPackageJsons(dir, results = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return results;
  }
   
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      findAllPackageJsons(path.join(dir, entry.name), results);
    } else if (entry.name === 'package.json') {
      results.push(path.join(dir, entry.name));
    }
  }
  
  return results;
}

function analyzePackageJson(pkgPath) {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    return null;
  }
  
  const pkgDir = path.dirname(pkgPath);
  const vulnerabilities = [];
  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
  
  if (allDeps.next) {
    let version = allDeps.next;
    let installedVersion = null;
    let displayVersion = version;
    
    if (isUnparseableVersionSpec(version) || !parseVersion(version)) {
      installedVersion = getInstalledVersion(pkgDir, 'next');
      if (installedVersion) {
        displayVersion = `${version} (installed: ${installedVersion})`;
        version = installedVersion;
      }
    }
    
    const check = isNextVersionVulnerable(version);
    if (check.vulnerable) {
      const patch = getNextPatchedVersion(version);
      vulnerabilities.push({
        package: 'next',
        current: displayVersion,
        patched: patch?.recommended || null,
        alternative: patch?.alternative || null,
        note: patch?.note || null,
        inDeps: !!pkg.dependencies?.next,
        inDevDeps: !!pkg.devDependencies?.next,
      });
    } else if (isUnparseableVersionSpec(allDeps.next) && !installedVersion) {
      vulnerabilities.push({
        package: 'next',
        current: allDeps.next,
        patched: '15.5.7',
        note: 'Could not determine installed version - run "npm install" first, or pin to a safe version',
        inDeps: !!pkg.dependencies?.next,
        inDevDeps: !!pkg.devDependencies?.next,
      });
    }
  }
  
  for (const rscPkg of REACT_RSC_PACKAGES) {
    if (allDeps[rscPkg]) {
      let version = allDeps[rscPkg];
      let displayVersion = version;
      
      if (isUnparseableVersionSpec(version)) {
        const installedVersion = getInstalledVersion(pkgDir, rscPkg);
        if (installedVersion) {
          displayVersion = `${version} (installed: ${installedVersion})`;
          version = installedVersion;
        }
      }
      
      if (isReactRscVersionVulnerable(version)) {
        vulnerabilities.push({
          package: rscPkg,
          current: displayVersion,
          patched: getReactRscPatchedVersion(version),
          inDeps: !!pkg.dependencies?.[rscPkg],
          inDevDeps: !!pkg.devDependencies?.[rscPkg],
        });
      }
    }
  }
  
  return {
    path: pkgPath,
    name: pkg.name || path.basename(path.dirname(pkgPath)),
    vulnerabilities,
  };
}

function detectPackageManager(cwd) {
  if (fs.existsSync(path.join(cwd, 'bun.lockb')) || fs.existsSync(path.join(cwd, 'bun.lock'))) {
    return 'bun';
  }
  if (fs.existsSync(path.join(cwd, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (fs.existsSync(path.join(cwd, 'yarn.lock'))) {
    return 'yarn';
  }
  return 'npm';
}

function getInstallCommand(packageManager) {
  switch (packageManager) {
    case 'bun': return 'bun install';
    case 'pnpm': return 'pnpm install';
    case 'yarn': return 'yarn install';
    default: return 'npm install';
  }
}

function applyFixes(pkgPath, vulnerabilities) {
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  let modified = false;
  
  for (const vuln of vulnerabilities) {
    if (!vuln.patched) continue;
    
    const newVersion = `^${vuln.patched}`;
    
    if (vuln.inDeps && pkg.dependencies?.[vuln.package]) {
      pkg.dependencies[vuln.package] = newVersion;
      modified = true;
    }
    if (vuln.inDevDeps && pkg.devDependencies?.[vuln.package]) {
      pkg.devDependencies[vuln.package] = newVersion;
      modified = true;
    }
  }
  
  if (modified) {
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  }
  
  return modified;
}

function runInstall(packageManager, cwd) {
  const commands = {
    npm: ['npm', ['install']],
    yarn: ['yarn', ['install']],
    pnpm: ['pnpm', ['install']],
    bun: ['bun', ['install']],
  };
  
  const [cmd, args] = commands[packageManager] || commands.npm;
  
  console.log(c('dim', `\n$ ${cmd} ${args.join(' ')}\n`));
  
  const result = spawnSync(cmd, args, {
    cwd,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  
  return result.status === 0;
}

async function run() {
  const cwd = process.cwd();
  const args = process.argv.slice(2);
  const shouldFix = args.includes('--fix') || args.includes('-f');
  const dryRun = args.includes('--dry-run') || args.includes('-d');
  const jsonOutput = args.includes('--json');
  
  if (!jsonOutput) {
    console.log('\n' + c('bold', '🔍 fix-react2shell-next') + c('dim', ' - CVE-2025-66478 vulnerability scanner\n'));
  }
  
  const packageJsonPaths = findAllPackageJsons(cwd);
  
  if (packageJsonPaths.length === 0) {
    if (jsonOutput) {
      console.log(JSON.stringify({ vulnerable: false, reason: 'no-package-json' }));
    } else {
      console.log(c('yellow', '⚠️  No package.json files found in current directory.\n'));
    }
    return;
  }
  
  if (!jsonOutput) {
    console.log(c('dim', `📂 Found ${packageJsonPaths.length} package.json file(s)\n`));
  }
  
  const allVulnerabilities = [];
  
  for (const pkgPath of packageJsonPaths) {
    const analysis = analyzePackageJson(pkgPath);
    if (analysis && analysis.vulnerabilities.length > 0) {
      allVulnerabilities.push(analysis);
    }
  }
  
  if (jsonOutput) {
    console.log(JSON.stringify({
      vulnerable: allVulnerabilities.length > 0,
      count: allVulnerabilities.length,
      files: allVulnerabilities,
    }, null, 2));
    return;
  }
  
  if (allVulnerabilities.length === 0) {
    console.log(c('green', '✓ No vulnerable packages found!'));
    console.log(c('dim', '  Your project is not affected by CVE-2025-66478.\n'));
    return;
  }
  
  console.log(c('red', `🚨 Found ${allVulnerabilities.length} vulnerable file(s):\n`));
  
  for (const file of allVulnerabilities) {
    const relativePath = path.relative(cwd, file.path) || 'package.json';
    console.log(c('yellow', `  📄 ${relativePath}`));
    
    for (const vuln of file.vulnerabilities) {
      console.log(c('dim', `     ${vuln.package}: `) + c('red', vuln.current) + c('dim', ' → ') + c('green', vuln.patched || '?'));
      if (vuln.note) {
        console.log(c('dim', `        ℹ️  ${vuln.note}`));
      }
    }
    console.log();
  }
  
  if (dryRun) {
    console.log(c('cyan', '📋 Dry run - no changes made.'));
    console.log(c('dim', '   Run with --fix to apply patches.\n'));
    return;
  }
  
  if (!shouldFix) {
    const isInteractive = process.stdin.isTTY;
    
    if (!isInteractive) {
      console.log(c('yellow', '⚠️  Running in non-interactive mode.'));
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
      rl.question(c('cyan', '🔧 Apply fixes? [Y/n] '), resolve);
    });
    rl.close();
    
    const confirmed = !answer || answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
    
    if (!confirmed) {
      console.log(c('yellow', '\n⚠️  Fix skipped. Your project remains vulnerable.\n'));
      process.exit(1);
      return;
    }
  }
  
  console.log(c('cyan', '\n🔧 Applying fixes...\n'));
  
  let fixedCount = 0;
  for (const file of allVulnerabilities) {
    const relativePath = path.relative(cwd, file.path) || 'package.json';
    const modified = applyFixes(file.path, file.vulnerabilities);
    if (modified) {
      console.log(c('green', `   ✓ Updated ${relativePath}`));
      fixedCount++;
    }
  }
  
  if (fixedCount === 0) {
    console.log(c('yellow', '   No files were modified (patches may require manual intervention).\n'));
    return;
  }
  
  const packageManager = detectPackageManager(cwd);
  console.log(c('dim', `\n📦 Package manager: ${packageManager}`));
  console.log(c('cyan', '🔄 Refreshing lockfile...\n'));
  
  const installSuccess = runInstall(packageManager, cwd);
  
  if (installSuccess) {
    console.log(c('green', '\n✅ Patches applied!'));
    console.log(c('dim', '   Remember to test your app and commit the changes.\n'));
  } else {
    console.log(c('yellow', '\n⚠️  Install command had issues.'));
    console.log(c('dim', '   The package.json files have been updated.'));
    console.log(c('dim', `   Please run "${getInstallCommand(packageManager)}" manually.\n`));
  }
}

module.exports = { run, findAllPackageJsons, analyzePackageJson, isNextVersionVulnerable };
