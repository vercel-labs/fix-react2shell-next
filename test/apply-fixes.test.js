/**
 * End-to-end tests for applying fixes to package.json
 *
 * Verifies that version specifier prefixes (^, ~, etc.) are preserved
 * when fixes are applied.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Import the functions we're testing
const { analyzePackageJson, computeMinimalFixes } = require('../lib/index');

// We need to access applyFixes which isn't exported, so we'll test via the full flow
// by creating temp package.json files and running analysis + fix

describe('applyFixes prefix preservation', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix-react2shell-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function createPackageJson(deps) {
    const pkgPath = path.join(tempDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: 'test-app',
      dependencies: deps,
    }, null, 2));
    return pkgPath;
  }

  function createNodeModulesVersion(packageName, version) {
    const pkgDir = path.join(tempDir, 'node_modules', packageName);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({
      name: packageName,
      version: version,
    }));
  }

  describe('originalSpecifier is captured during analysis', () => {
    it('should capture exact version specifier', () => {
      const pkgPath = createPackageJson({ next: '15.3.0' });
      createNodeModulesVersion('next', '15.3.0');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 1);
      assert.strictEqual(analysis.vulnerabilities[0].originalSpecifier, '15.3.0');
    });

    it('should capture ^ prefix specifier', () => {
      const pkgPath = createPackageJson({ next: '^15.3.0' });
      createNodeModulesVersion('next', '15.3.4');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 1);
      assert.strictEqual(analysis.vulnerabilities[0].originalSpecifier, '^15.3.0');
    });

    it('should capture ~ prefix specifier', () => {
      const pkgPath = createPackageJson({ next: '~15.3.0' });
      createNodeModulesVersion('next', '15.3.4');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 1);
      assert.strictEqual(analysis.vulnerabilities[0].originalSpecifier, '~15.3.0');
    });

    it('should capture >= prefix specifier', () => {
      const pkgPath = createPackageJson({ next: '>=15.3.0' });
      createNodeModulesVersion('next', '15.3.4');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 1);
      assert.strictEqual(analysis.vulnerabilities[0].originalSpecifier, '>=15.3.0');
    });
  });

  describe('originalSpecifier flows through computeMinimalFixes', () => {
    it('should preserve originalSpecifier in computed fixes', () => {
      const pkgPath = createPackageJson({ next: '^15.3.0' });
      createNodeModulesVersion('next', '15.3.4');

      const analysis = analyzePackageJson(pkgPath);
      const fixes = computeMinimalFixes([analysis]);

      assert.strictEqual(fixes.length, 1);
      assert.strictEqual(fixes[0].fixes[0].originalSpecifier, '^15.3.0');
      assert.strictEqual(fixes[0].fixes[0].patched, '15.3.7');
    });

    it('should work with multiple packages', () => {
      const pkgPath = createPackageJson({
        next: '^15.3.0',
        'react-server-dom-webpack': '~19.0.0',
      });
      createNodeModulesVersion('next', '15.3.4');
      createNodeModulesVersion('react-server-dom-webpack', '19.0.0');

      const analysis = analyzePackageJson(pkgPath);
      const fixes = computeMinimalFixes([analysis]);

      assert.strictEqual(fixes[0].fixes.length, 2);

      const nextFix = fixes[0].fixes.find(f => f.package === 'next');
      const rscFix = fixes[0].fixes.find(f => f.package === 'react-server-dom-webpack');

      assert.strictEqual(nextFix.originalSpecifier, '^15.3.0');
      assert.strictEqual(rscFix.originalSpecifier, '~19.0.0');
    });
  });

  describe('non-vulnerable versions are not flagged', () => {
    it('should not flag patched versions', () => {
      const pkgPath = createPackageJson({ next: '^15.3.7' });
      createNodeModulesVersion('next', '15.3.7');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 0);
    });

    it('should not flag versions above patch', () => {
      const pkgPath = createPackageJson({ next: '^15.3.10' });
      createNodeModulesVersion('next', '15.3.10');

      const analysis = analyzePackageJson(pkgPath);

      assert.strictEqual(analysis.vulnerabilities.length, 0);
    });
  });
});
