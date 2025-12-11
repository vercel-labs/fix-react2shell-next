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

function isUnparseableVersionSpec(version) {
  if (!version) return true;
  const unparseable = ['latest', 'next', 'canary', '*', 'x'];
  const cleaned = version.replace(/^[\^~>=<]+/, '').trim().toLowerCase();
  return unparseable.includes(cleaned) ||
         cleaned.startsWith('npm:') ||
         cleaned.startsWith('catalog:') ||
         cleaned.startsWith('workspace:') ||
         cleaned.includes('/');
}

function hasRangeSpecifier(version) {
  if (!version) return false;
  // Check if version has range specifiers that could resolve to different versions
  return /^[\^~>=<]/.test(version.trim()) || version.includes(' ') || version.includes('||');
}

function cleanVersion(version) {
  return version.replace(/^[\^~>=<]+/, '').trim();
}

/**
 * Extract the prefix from a version specifier (^, ~, >=, etc.)
 * Returns empty string for exact versions
 */
function getVersionPrefix(version) {
  if (!version) return '';
  const match = version.match(/^([\^~>=<]+)/);
  return match ? match[1] : '';
}

/**
 * Apply a prefix to a version, preserving range semantics
 * If original had ^, new version gets ^
 * If original had ~, new version gets ~
 * If original was exact, new version is exact
 */
function applyVersionPrefix(originalVersion, newVersion) {
  const prefix = getVersionPrefix(originalVersion);
  return prefix + newVersion;
}

module.exports = {
  parseVersion,
  compareVersions,
  isUnparseableVersionSpec,
  hasRangeSpecifier,
  cleanVersion,
  getVersionPrefix,
  applyVersionPrefix,
};
