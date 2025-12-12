/**
 * Lock File Scanner for React 19 Vulnerabilities
 * Scans package-lock.json, yarn.lock, pnpm-lock.yaml, and bun.lockb
 * to detect vulnerable React 19 packages in the dependency tree
 */

const fs = require("fs");
const path = require("path");
const { parseVersion } = require("./version");
const { vulnerabilities } = require("../vulnerabilities");

/**
 * React packages to scan in lock files
 */
const REACT_PACKAGES = [
  "react",
  "react-dom",
  "react-server-dom-webpack",
  "react-server-dom-parcel",
  "react-server-dom-turbopack",
];

/**
 * Parse npm package-lock.json (v1, v2, v3)
 */
function parseNpmLockfile(lockfilePath) {
  try {
    const content = JSON.parse(fs.readFileSync(lockfilePath, "utf8"));
    const packages = [];

    // Handle lockfile v2/v3 format
    if (content.packages) {
      for (const [packagePath, info] of Object.entries(content.packages)) {
        const packageName = packagePath.replace(/^node_modules\//, "");
        if (
          packageName &&
          REACT_PACKAGES.includes(packageName) &&
          info.version
        ) {
          packages.push({
            name: packageName,
            version: info.version,
            resolved: info.resolved || null,
          });
        }
      }
    }

    // Handle lockfile v1 format
    if (content.dependencies) {
      extractNpmDependencies(content.dependencies, packages);
    }

    return packages;
  } catch (e) {
    return [];
  }
}

/**
 * Recursively extract dependencies from npm lockfile v1
 */
function extractNpmDependencies(deps, results) {
  for (const [name, info] of Object.entries(deps)) {
    if (REACT_PACKAGES.includes(name) && info.version) {
      results.push({
        name,
        version: info.version,
        resolved: info.resolved || null,
      });
    }
    if (info.dependencies) {
      extractNpmDependencies(info.dependencies, results);
    }
  }
}

/**
 * Parse yarn.lock file
 */
function parseYarnLockfile(lockfilePath) {
  try {
    const content = fs.readFileSync(lockfilePath, "utf8");
    const packages = [];
    const lines = content.split("\n");

    let currentPackage = null;
    let currentVersion = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match package declaration: "package@version", package@version:
      const packageMatch = line.match(/^"?([^@\s]+)@[^"]*"?:?\s*$/);
      if (packageMatch) {
        const packageName = packageMatch[1];
        if (REACT_PACKAGES.includes(packageName)) {
          currentPackage = packageName;
        } else {
          currentPackage = null;
        }
        continue;
      }

      // Match version line: version "19.0.0"
      if (currentPackage) {
        const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
        if (versionMatch) {
          packages.push({
            name: currentPackage,
            version: versionMatch[1],
            resolved: null,
          });
          currentPackage = null;
        }
      }
    }

    return packages;
  } catch (e) {
    return [];
  }
}

/**
 * Parse pnpm-lock.yaml file
 */
function parsePnpmLockfile(lockfilePath) {
  try {
    const content = fs.readFileSync(lockfilePath, "utf8");
    const packages = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match package entries like:
      // /react@19.0.0:
      // /react-dom@19.0.0(react@19.0.0):
      for (const packageName of REACT_PACKAGES) {
        const regex = new RegExp(`^\\s*['/]${packageName}@([^:(/\\s]+)`);
        const match = line.match(regex);
        if (match) {
          packages.push({
            name: packageName,
            version: match[1],
            resolved: null,
          });
        }
      }
    }

    return packages;
  } catch (e) {
    return [];
  }
}

/**
 * Parse bun.lockb file (binary format - limited support)
 * We can only detect by checking if the file exists and then
 * rely on package-manager.js to get installed versions
 */
function parseBunLockfile(lockfilePath) {
  // Bun's lockfile is binary, so we can't parse it directly
  // Return empty array to trigger fallback to package manager detection
  return [];
}

/**
 * Scan a directory for lock files and extract React 19 packages
 */
function scanLockfile(dir) {
  const lockfiles = [
    { name: "package-lock.json", parser: parseNpmLockfile },
    { name: "yarn.lock", parser: parseYarnLockfile },
    { name: "pnpm-lock.yaml", parser: parsePnpmLockfile },
    { name: "bun.lockb", parser: parseBunLockfile },
    { name: "bun.lock", parser: parseBunLockfile },
  ];

  for (const lockfile of lockfiles) {
    const lockfilePath = path.join(dir, lockfile.name);
    if (fs.existsSync(lockfilePath)) {
      const packages = lockfile.parser(lockfilePath);
      if (packages.length > 0) {
        return {
          lockfile: lockfile.name,
          path: lockfilePath,
          packages,
        };
      }
    }
  }

  return null;
}

/**
 * Check if a React package version is vulnerable to any CVE
 */
function checkPackageVulnerability(packageName, version) {
  const affectedCves = [];

  for (const vuln of vulnerabilities) {
    if (!vuln.packages.includes(packageName)) continue;

    const check = vuln.isVulnerable(packageName, version);
    if (check.vulnerable) {
      const patch = vuln.getPatchedVersion(packageName, version);
      affectedCves.push({
        id: vuln.id,
        severity: vuln.severity,
        description: vuln.description,
        patchedVersion: patch?.recommended || null,
        alternative: patch?.alternative || null,
        note: patch?.note || null,
      });
    }
  }

  return affectedCves;
}

/**
 * Analyze lock file for vulnerabilities
 */
function analyzeLockfile(lockfileData) {
  if (!lockfileData || !lockfileData.packages) return null;

  const vulnerablePackages = [];
  const seenPackages = new Map();

  for (const pkg of lockfileData.packages) {
    // Deduplicate packages (same package might appear multiple times)
    const key = `${pkg.name}@${pkg.version}`;
    if (seenPackages.has(key)) continue;
    seenPackages.set(key, true);

    const cves = checkPackageVulnerability(pkg.name, pkg.version);
    if (cves.length > 0) {
      // Find highest patched version across all CVEs
      let highestVersion = null;
      for (const cve of cves) {
        if (cve.patchedVersion) {
          if (!highestVersion) {
            highestVersion = cve.patchedVersion;
          } else {
            const current = parseVersion(cve.patchedVersion);
            const highest = parseVersion(highestVersion);

            if (current && highest) {
              if (
                current.major > highest.major ||
                (current.major === highest.major &&
                  current.minor > highest.minor) ||
                (current.major === highest.major &&
                  current.minor === highest.minor &&
                  current.patch > highest.patch)
              ) {
                highestVersion = cve.patchedVersion;
              }
            }
          }
        }
      }

      vulnerablePackages.push({
        package: pkg.name,
        currentVersion: pkg.version,
        patchedVersion: highestVersion,
        cves: cves.map((c) => c.id),
        severity: cves[0].severity, // Use highest severity
        resolved: pkg.resolved,
      });
    }
  }

  if (vulnerablePackages.length === 0) return null;

  return {
    lockfile: lockfileData.lockfile,
    path: lockfileData.path,
    vulnerabilities: vulnerablePackages,
  };
}

/**
 * Find and scan all lock files in a directory tree
 */
function findAndScanLockfiles(dir, results = []) {
  const SKIP_DIRS = new Set([
    "node_modules",
    ".next",
    ".turbo",
    ".git",
    "dist",
    "build",
    ".output",
    ".nuxt",
    ".vercel",
    "coverage",
  ]);

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return results;
  }

  // Check current directory for lock files
  const lockfileData = scanLockfile(dir);
  if (lockfileData) {
    const analysis = analyzeLockfile(lockfileData);
    if (analysis) {
      results.push(analysis);
    }
  }

  // Recurse into subdirectories
  for (const entry of entries) {
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      findAndScanLockfiles(path.join(dir, entry.name), results);
    }
  }

  return results;
}

module.exports = {
  scanLockfile,
  analyzeLockfile,
  findAndScanLockfiles,
  checkPackageVulnerability,
  REACT_PACKAGES,
};
