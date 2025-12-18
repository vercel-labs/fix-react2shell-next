/**
 * Vulnerability Registry
 * Loads and exports all known vulnerability modules
 */

const vulnerabilities = [
  require('./cve-2025-66478'),  // React2Shell - RCE (critical)
  require('./cve-2025-55184'),  // DoS (high)
  require('./cve-2025-55183'),  // Source Code Exposure (medium)
  require('./cve-2025-55182'),  // React Core RCE (critical)
  require('./cve-2025-67779'),  // DoS Incomplete Fix Follow-Up (high)
];

// Get all unique package names across all vulnerabilities
function getAllPackages() {
  const packages = new Set();
  for (const vuln of vulnerabilities) {
    for (const pkg of vuln.packages) {
      packages.add(pkg);
    }
  }
  return Array.from(packages);
}

// Get all vulnerabilities that apply to a specific package
function getVulnerabilitiesForPackage(packageName) {
  return vulnerabilities.filter(v => v.packages.includes(packageName));
}

module.exports = {
  vulnerabilities,
  getAllPackages,
  getVulnerabilitiesForPackage,
};
