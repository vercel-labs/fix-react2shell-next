/**
 * Tests for lock file scanner functionality
 */

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  scanLockfile,
  analyzeLockfile,
  checkPackageVulnerability,
  REACT_PACKAGES,
} = require("../lib/utils/lockfile-scanner");

describe("Lock File Scanner", () => {
  let tempDir;

  beforeEach(() => {
    // Create temporary directory for test files
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "lockfile-test-"));
  });

  afterEach(() => {
    // Clean up temporary directory
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe("scanLockfile", () => {
    it("should detect npm package-lock.json (v3 format)", () => {
      const lockfile = {
        name: "test-project",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "test-project",
            version: "1.0.0",
          },
          "node_modules/react": {
            version: "19.0.0",
            resolved: "https://registry.npmjs.org/react/-/react-19.0.0.tgz",
          },
          "node_modules/react-dom": {
            version: "19.0.0",
            resolved:
              "https://registry.npmjs.org/react-dom/-/react-dom-19.0.0.tgz",
          },
        },
      };

      fs.writeFileSync(
        path.join(tempDir, "package-lock.json"),
        JSON.stringify(lockfile, null, 2)
      );

      const result = scanLockfile(tempDir);
      assert.ok(result, "Should return a result");
      assert.strictEqual(result.lockfile, "package-lock.json");
      assert.strictEqual(result.packages.length, 2);
      assert.ok(
        result.packages.some(
          (p) => p.name === "react" && p.version === "19.0.0"
        )
      );
      assert.ok(
        result.packages.some(
          (p) => p.name === "react-dom" && p.version === "19.0.0"
        )
      );
    });

    it("should detect yarn.lock format", () => {
      const lockfile = `
# yarn lockfile v1

react@19.0.0:
  version "19.0.0"
  resolved "https://registry.yarnpkg.com/react/-/react-19.0.0.tgz"

react-dom@19.0.0:
  version "19.0.0"
  resolved "https://registry.yarnpkg.com/react-dom/-/react-dom-19.0.0.tgz"
`;

      fs.writeFileSync(path.join(tempDir, "yarn.lock"), lockfile);

      const result = scanLockfile(tempDir);
      assert.ok(result, "Should return a result");
      assert.strictEqual(result.lockfile, "yarn.lock");
      assert.strictEqual(result.packages.length, 2);
    });

    it("should detect pnpm-lock.yaml format", () => {
      const lockfile = `
lockfileVersion: '6.0'

dependencies:
  react:
    specifier: ^19.0.0
    version: 19.0.0

packages:
  /react@19.0.0:
    resolution: {integrity: sha512-...}
    dev: false

  /react-dom@19.0.0(react@19.0.0):
    resolution: {integrity: sha512-...}
    dev: false
`;

      fs.writeFileSync(path.join(tempDir, "pnpm-lock.yaml"), lockfile);

      const result = scanLockfile(tempDir);
      assert.ok(result, "Should return a result");
      assert.strictEqual(result.lockfile, "pnpm-lock.yaml");
      assert.ok(
        result.packages.length >= 1,
        "Should detect at least one package"
      );
    });

    it("should return null when no lockfile exists", () => {
      const result = scanLockfile(tempDir);
      assert.strictEqual(result, null);
    });

    it("should only extract React packages", () => {
      const lockfile = {
        name: "test-project",
        lockfileVersion: 3,
        packages: {
          "node_modules/react": {
            version: "19.0.0",
          },
          "node_modules/lodash": {
            version: "4.17.21",
          },
          "node_modules/express": {
            version: "4.18.0",
          },
        },
      };

      fs.writeFileSync(
        path.join(tempDir, "package-lock.json"),
        JSON.stringify(lockfile, null, 2)
      );

      const result = scanLockfile(tempDir);
      assert.strictEqual(result.packages.length, 1);
      assert.strictEqual(result.packages[0].name, "react");
    });
  });

  describe("checkPackageVulnerability", () => {
    it("should detect vulnerable React 19.0.0", () => {
      const cves = checkPackageVulnerability(
        "react-server-dom-webpack",
        "19.0.0"
      );
      assert.ok(cves.length > 0, "Should find vulnerabilities");
      assert.ok(cves.some((cve) => cve.id === "CVE-2025-66478"));
    });

    it("should detect vulnerable React 19.1.0", () => {
      const cves = checkPackageVulnerability(
        "react-server-dom-webpack",
        "19.1.0"
      );
      assert.ok(cves.length > 0, "Should find vulnerabilities");
    });

    it("should not flag patched React 19.0.2", () => {
      const cves = checkPackageVulnerability(
        "react-server-dom-webpack",
        "19.0.2"
      );
      // 19.0.2 might still be flagged by other CVEs, but should not be flagged by 66478
      const cve66478 = cves.find((cve) => cve.id === "CVE-2025-66478");
      assert.ok(!cve66478, "CVE-2025-66478 should not flag 19.0.2");
    });

    it("should not flag non-React packages", () => {
      const cves = checkPackageVulnerability("lodash", "4.17.21");
      assert.strictEqual(cves.length, 0);
    });

    it("should return patched version recommendations", () => {
      const cves = checkPackageVulnerability(
        "react-server-dom-webpack",
        "19.0.0"
      );
      assert.ok(cves.length > 0);
      assert.ok(cves[0].patchedVersion, "Should have a patched version");
    });
  });

  describe("analyzeLockfile", () => {
    it("should analyze lockfile data and find vulnerabilities", () => {
      const lockfileData = {
        lockfile: "package-lock.json",
        path: path.join(tempDir, "package-lock.json"),
        packages: [
          {
            name: "react-server-dom-webpack",
            version: "19.0.0",
            resolved: null,
          },
          {
            name: "react-server-dom-parcel",
            version: "19.1.0",
            resolved: null,
          },
        ],
      };

      const result = analyzeLockfile(lockfileData);
      assert.ok(result, "Should return analysis result");
      assert.strictEqual(result.lockfile, "package-lock.json");
      assert.ok(
        result.vulnerabilities.length > 0,
        "Should find vulnerabilities"
      );
    });

    it("should deduplicate packages", () => {
      const lockfileData = {
        lockfile: "package-lock.json",
        path: path.join(tempDir, "package-lock.json"),
        packages: [
          {
            name: "react-server-dom-webpack",
            version: "19.0.0",
            resolved: null,
          },
          {
            name: "react-server-dom-webpack",
            version: "19.0.0",
            resolved: null,
          },
          {
            name: "react-server-dom-webpack",
            version: "19.0.0",
            resolved: null,
          },
        ],
      };

      const result = analyzeLockfile(lockfileData);
      assert.ok(result);
      assert.strictEqual(
        result.vulnerabilities.length,
        1,
        "Should deduplicate packages"
      );
    });

    it("should return null when no vulnerabilities found", () => {
      const lockfileData = {
        lockfile: "package-lock.json",
        path: path.join(tempDir, "package-lock.json"),
        packages: [{ name: "react", version: "18.2.0", resolved: null }],
      };

      const result = analyzeLockfile(lockfileData);
      assert.strictEqual(result, null);
    });

    it("should include CVE IDs and severity", () => {
      const lockfileData = {
        lockfile: "package-lock.json",
        path: path.join(tempDir, "package-lock.json"),
        packages: [
          {
            name: "react-server-dom-webpack",
            version: "19.0.0",
            resolved: null,
          },
        ],
      };

      const result = analyzeLockfile(lockfileData);
      assert.ok(result);
      assert.ok(result.vulnerabilities[0].cves.length > 0);
      assert.ok(result.vulnerabilities[0].severity);
      assert.ok(result.vulnerabilities[0].patchedVersion);
    });
  });

  describe("REACT_PACKAGES constant", () => {
    it("should include core React packages", () => {
      assert.ok(REACT_PACKAGES.includes("react"));
      assert.ok(REACT_PACKAGES.includes("react-dom"));
      assert.ok(REACT_PACKAGES.includes("react-server-dom-webpack"));
      assert.ok(REACT_PACKAGES.includes("react-server-dom-parcel"));
      assert.ok(REACT_PACKAGES.includes("react-server-dom-turbopack"));
    });
  });

  describe("Edge cases", () => {
    it("should handle malformed lockfile gracefully", () => {
      fs.writeFileSync(
        path.join(tempDir, "package-lock.json"),
        "not valid json {"
      );

      const result = scanLockfile(tempDir);
      assert.strictEqual(result, null);
    });

    it("should handle empty lockfile", () => {
      fs.writeFileSync(path.join(tempDir, "package-lock.json"), "{}");

      const result = scanLockfile(tempDir);
      assert.strictEqual(result, null);
    });

    it("should handle lockfile with no React packages", () => {
      const lockfile = {
        lockfileVersion: 3,
        packages: {
          "node_modules/lodash": { version: "4.17.21" },
          "node_modules/express": { version: "4.18.0" },
        },
      };

      fs.writeFileSync(
        path.join(tempDir, "package-lock.json"),
        JSON.stringify(lockfile, null, 2)
      );

      const result = scanLockfile(tempDir);
      assert.strictEqual(result, null);
    });
  });
});
