/**
 * Vulnerability Registry
 * Loads and exports all known vulnerability modules
 */

const vulnerabilities = [
  require('./cve-2025-66478'),  // React2Shell: RCE in Next.js App Router (critical)
  require('./cve-2025-55184'),  // DoS: Infinite loops in React Server Components (high)
  require('./cve-2025-55183'),  // Source Code Exposure: Server Functions leak source (medium)
  require('./cve-2025-55182'),  // RCE: Unsafe deserialization in React Server Components (critical)
  require('./cve-2025-67779'),  // DoS Follow-up: Incomplete fix for CVE-2025-55184 (high)
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
