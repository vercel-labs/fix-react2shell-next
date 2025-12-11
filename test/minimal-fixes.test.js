/**
 * Tests for computing minimal fixes across all CVEs
 *
 * When a package is vulnerable to multiple CVEs, the tool should select
 * the lowest version that fixes ALL vulnerabilities. Since newer patches
 * include all previous fixes, this means selecting the HIGHEST patched
 * version among all applicable CVEs.
 *
 * Example: Next.js 15.3.0 is vulnerable to:
 * - CVE-2025-66478 (React2Shell): patched in 15.3.6
 * - CVE-2025-55184 (DoS): patched in 15.3.7
 * - CVE-2025-55183 (Source Code Exposure): patched in 15.3.7
 *
 * The tool should recommend 15.3.7 (the highest), not 15.3.6.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { computeMinimalFixes } = require('../lib/index');
const cve66478 = require('../lib/vulnerabilities/cve-2025-66478');
const cve55184 = require('../lib/vulnerabilities/cve-2025-55184');
const cve55183 = require('../lib/vulnerabilities/cve-2025-55183');

describe('computeMinimalFixes', () => {
  describe('selects highest patched version across all CVEs', () => {
    it('should select 15.0.6 for Next.js 15.0.x (covers all 3 CVEs)', () => {
      // 15.0.x patch versions:
      // - CVE-2025-66478: 15.0.5
      // - CVE-2025-55184: 15.0.6
      // - CVE-2025-55183: 15.0.6
      // Expected: 15.0.6 (highest)

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.0.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.0.5' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.0.6' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.0.6' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes.length, 1);
      assert.strictEqual(fixes[0].fixes.length, 1);
      assert.strictEqual(fixes[0].fixes[0].package, 'next');
      assert.strictEqual(fixes[0].fixes[0].patched, '15.0.6');
      assert.deepStrictEqual(fixes[0].fixes[0].cves, ['CVE-2025-66478', 'CVE-2025-55184', 'CVE-2025-55183']);
    });

    it('should select 15.1.10 for Next.js 15.1.x (covers all 3 CVEs)', () => {
      // 15.1.x patch versions:
      // - CVE-2025-66478: 15.1.9
      // - CVE-2025-55184: 15.1.10
      // - CVE-2025-55183: 15.1.10
      // Expected: 15.1.10 (highest)

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.1.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.1.9' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.1.10' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.1.10' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes[0].fixes[0].patched, '15.1.10');
    });

    it('should select 15.2.7 for Next.js 15.2.x (covers all 3 CVEs)', () => {
      // 15.2.x patch versions:
      // - CVE-2025-66478: 15.2.6
      // - CVE-2025-55184: 15.2.7
      // - CVE-2025-55183: 15.2.7

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.2.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.2.6' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.2.7' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.2.7' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '15.2.7');
    });

    it('should select 15.3.7 for Next.js 15.3.x (covers all 3 CVEs)', () => {
      // 15.3.x patch versions:
      // - CVE-2025-66478: 15.3.6
      // - CVE-2025-55184: 15.3.7
      // - CVE-2025-55183: 15.3.7

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.3.4',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.3.6' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.3.7' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.3.7' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '15.3.7');
    });

    it('should select 15.4.9 for Next.js 15.4.x (covers all 3 CVEs)', () => {
      // 15.4.x patch versions:
      // - CVE-2025-66478: 15.4.8
      // - CVE-2025-55184: 15.4.9
      // - CVE-2025-55183: 15.4.9

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.4.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.4.8' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.4.9' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.4.9' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '15.4.9');
    });

    it('should select 15.5.8 for Next.js 15.5.x (covers all 3 CVEs)', () => {
      // 15.5.x patch versions:
      // - CVE-2025-66478: 15.5.7
      // - CVE-2025-55184: 15.5.8
      // - CVE-2025-55183: 15.5.8

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.5.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.5.7' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.5.8' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.5.8' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '15.5.8');
    });

    it('should select 16.0.9 for Next.js 16.0.x (covers all 3 CVEs)', () => {
      // 16.0.x patch versions:
      // - CVE-2025-66478: 16.0.7
      // - CVE-2025-55184: 16.0.9
      // - CVE-2025-55183: 16.0.9

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '16.0.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '16.0.7' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '16.0.9' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '16.0.9' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '16.0.9');
    });

    it('should select 15.6.0-canary.59 for 15.x canaries (covers all 3 CVEs)', () => {
      // 15.x canary patch versions:
      // - CVE-2025-66478: 15.6.0-canary.58
      // - CVE-2025-55184: 15.6.0-canary.59
      // - CVE-2025-55183: 15.6.0-canary.59

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.6.0-canary.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.6.0-canary.58' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.6.0-canary.59' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.6.0-canary.59' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '15.6.0-canary.59');
    });

    it('should select 16.1.0-canary.18 for 16.x canaries (covers all 3 CVEs)', () => {
      // 16.x canary patch versions:
      // - CVE-2025-66478: 16.1.0-canary.12
      // - CVE-2025-55184: 16.1.0-canary.18
      // - CVE-2025-55183: 16.1.0-canary.18

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '16.1.0-canary.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '16.1.0-canary.12' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '16.1.0-canary.18' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '16.1.0-canary.18' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '16.1.0-canary.18');
    });
  });

  describe('handles versions only affected by some CVEs', () => {
    it('should select 14.2.34 for Next.js 14.x (only DoS, not Source Code Exposure)', () => {
      // 14.x is only vulnerable to CVE-2025-66478 (canaries only) and CVE-2025-55184 (DoS)
      // NOT vulnerable to CVE-2025-55183 (Source Code Exposure)

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '14.2.0',
          cves: [
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '14.2.34' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes[0].fixes[0].patched, '14.2.34');
      assert.deepStrictEqual(fixes[0].fixes[0].cves, ['CVE-2025-55184']);
    });

    it('should select 14.2.34 for Next.js 13.x (only DoS)', () => {
      // 13.x (>= 13.3) is only vulnerable to CVE-2025-55184 (DoS)
      // NOT vulnerable to CVE-2025-66478 or CVE-2025-55183

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '13.4.0',
          cves: [
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '14.2.34' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes[0].fixes[0].patched, '14.2.34');
    });
  });

  describe('handles React RSC packages', () => {
    it('should select 19.0.2 for react-server-dom-webpack@19.0.0', () => {
      // React RSC 19.0.x patch versions for DoS and Source Code Exposure:
      // - CVE-2025-66478: 19.0.1
      // - CVE-2025-55184: 19.0.2
      // - CVE-2025-55183: 19.0.2

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'react-server-dom-webpack',
          current: '19.0.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '19.0.1' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '19.0.2' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '19.0.2' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '19.0.2');
    });

    it('should select 19.1.3 for react-server-dom-webpack@19.1.0', () => {
      // React RSC 19.1.x patch versions:
      // - CVE-2025-66478: 19.1.2
      // - CVE-2025-55184: 19.1.3
      // - CVE-2025-55183: 19.1.3

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'react-server-dom-webpack',
          current: '19.1.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '19.1.2' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '19.1.3' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '19.1.3' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '19.1.3');
    });

    it('should select 19.2.2 for react-server-dom-webpack@19.2.0', () => {
      // React RSC 19.2.x patch versions:
      // - CVE-2025-66478: 19.2.1
      // - CVE-2025-55184: 19.2.2
      // - CVE-2025-55183: 19.2.2

      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'react-server-dom-webpack',
          current: '19.2.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '19.2.1' },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '19.2.2' },
            { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '19.2.2' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, '19.2.2');
    });
  });

  describe('handles multiple packages in same file', () => {
    it('should compute correct fixes for both next and react-server-dom-webpack', () => {
      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [
          {
            package: 'next',
            current: '15.3.0',
            cves: [
              { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.3.6' },
              { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.3.7' },
              { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '15.3.7' },
            ],
            inDeps: true,
            inDevDeps: false,
          },
          {
            package: 'react-server-dom-webpack',
            current: '19.1.0',
            cves: [
              { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '19.1.2' },
              { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '19.1.3' },
              { id: 'CVE-2025-55183', severity: 'medium', patchedVersion: '19.1.3' },
            ],
            inDeps: true,
            inDevDeps: false,
          },
        ],
      }];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes.length, 1);
      assert.strictEqual(fixes[0].fixes.length, 2);

      const nextFix = fixes[0].fixes.find(f => f.package === 'next');
      const rscFix = fixes[0].fixes.find(f => f.package === 'react-server-dom-webpack');

      assert.strictEqual(nextFix.patched, '15.3.7');
      assert.strictEqual(rscFix.patched, '19.1.3');
    });
  });

  describe('handles multiple files', () => {
    it('should compute fixes independently for each package.json', () => {
      const analysisResults = [
        {
          path: '/app1/package.json',
          name: 'app1',
          vulnerabilities: [{
            package: 'next',
            current: '15.3.0',
            cves: [
              { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '15.3.6' },
              { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.3.7' },
            ],
            inDeps: true,
            inDevDeps: false,
          }],
        },
        {
          path: '/app2/package.json',
          name: 'app2',
          vulnerabilities: [{
            package: 'next',
            current: '16.0.0',
            cves: [
              { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: '16.0.7' },
              { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '16.0.9' },
            ],
            inDeps: true,
            inDevDeps: false,
          }],
        },
      ];

      const fixes = computeMinimalFixes(analysisResults);

      assert.strictEqual(fixes.length, 2);

      const app1Fix = fixes.find(f => f.path === '/app1/package.json');
      const app2Fix = fixes.find(f => f.path === '/app2/package.json');

      assert.strictEqual(app1Fix.fixes[0].patched, '15.3.7');
      assert.strictEqual(app2Fix.fixes[0].patched, '16.0.9');
    });
  });

  describe('edge cases', () => {
    it('should handle empty vulnerabilities array', () => {
      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes.length, 0);
    });

    it('should handle missing patchedVersion gracefully', () => {
      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.0.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: null },
            { id: 'CVE-2025-55184', severity: 'high', patchedVersion: '15.0.6' },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      // Should still return 15.0.6 as the highest available patch
      assert.strictEqual(fixes[0].fixes[0].patched, '15.0.6');
    });

    it('should return null patched if all CVEs have null patchedVersion', () => {
      const analysisResults = [{
        path: '/test/package.json',
        name: 'test-app',
        vulnerabilities: [{
          package: 'next',
          current: '15.0.0',
          cves: [
            { id: 'CVE-2025-66478', severity: 'critical', patchedVersion: null },
          ],
          inDeps: true,
          inDevDeps: false,
        }],
      }];

      const fixes = computeMinimalFixes(analysisResults);
      assert.strictEqual(fixes[0].fixes[0].patched, null);
    });
  });
});

describe('integration: getPatchedVersion across CVEs', () => {
  describe('verifies each CVE module returns correct patch versions', () => {
    const testCases = [
      // Next.js 15.0.x
      { version: '15.0.0', expected66478: '15.0.5', expected55184: '15.0.6', expected55183: '15.0.6', expectedFinal: '15.0.6' },
      // Next.js 15.1.x
      { version: '15.1.0', expected66478: '15.1.9', expected55184: '15.1.10', expected55183: '15.1.10', expectedFinal: '15.1.10' },
      // Next.js 15.2.x
      { version: '15.2.0', expected66478: '15.2.6', expected55184: '15.2.7', expected55183: '15.2.7', expectedFinal: '15.2.7' },
      // Next.js 15.3.x
      { version: '15.3.0', expected66478: '15.3.6', expected55184: '15.3.7', expected55183: '15.3.7', expectedFinal: '15.3.7' },
      // Next.js 15.4.x
      { version: '15.4.0', expected66478: '15.4.8', expected55184: '15.4.9', expected55183: '15.4.9', expectedFinal: '15.4.9' },
      // Next.js 15.5.x
      { version: '15.5.0', expected66478: '15.5.7', expected55184: '15.5.8', expected55183: '15.5.8', expectedFinal: '15.5.8' },
      // Next.js 16.0.x
      { version: '16.0.0', expected66478: '16.0.7', expected55184: '16.0.9', expected55183: '16.0.9', expectedFinal: '16.0.9' },
    ];

    for (const tc of testCases) {
      it(`should recommend ${tc.expectedFinal} for Next.js ${tc.version}`, () => {
        const patch66478 = cve66478.getPatchedVersion('next', tc.version);
        const patch55184 = cve55184.getPatchedVersion('next', tc.version);
        const patch55183 = cve55183.getPatchedVersion('next', tc.version);

        assert.strictEqual(patch66478?.recommended, tc.expected66478, `CVE-2025-66478 patch mismatch`);
        assert.strictEqual(patch55184?.recommended, tc.expected55184, `CVE-2025-55184 patch mismatch`);
        assert.strictEqual(patch55183?.recommended, tc.expected55183, `CVE-2025-55183 patch mismatch`);

        // The final recommendation should be the highest
        const patches = [patch66478?.recommended, patch55184?.recommended, patch55183?.recommended].filter(Boolean);
        const highest = patches.sort((a, b) => {
          const partsA = a.split('.').map(Number);
          const partsB = b.split('.').map(Number);
          for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
            if ((partsA[i] || 0) !== (partsB[i] || 0)) {
              return (partsB[i] || 0) - (partsA[i] || 0);
            }
          }
          return 0;
        })[0];

        assert.strictEqual(highest, tc.expectedFinal, `Final recommendation mismatch for ${tc.version}`);
      });
    }
  });

  describe('canary version patches', () => {
    it('should recommend 15.6.0-canary.59 for 15.x canaries', () => {
      const patch66478 = cve66478.getPatchedVersion('next', '15.6.0-canary.0');
      const patch55184 = cve55184.getPatchedVersion('next', '15.6.0-canary.0');
      const patch55183 = cve55183.getPatchedVersion('next', '15.6.0-canary.0');

      assert.strictEqual(patch66478?.recommended, '15.6.0-canary.58');
      assert.strictEqual(patch55184?.recommended, '15.6.0-canary.59');
      assert.strictEqual(patch55183?.recommended, '15.6.0-canary.59');
    });

    it('should recommend 16.1.0-canary.18 for 16.x canaries', () => {
      const patch66478 = cve66478.getPatchedVersion('next', '16.1.0-canary.0');
      const patch55184 = cve55184.getPatchedVersion('next', '16.1.0-canary.0');
      const patch55183 = cve55183.getPatchedVersion('next', '16.1.0-canary.0');

      assert.strictEqual(patch66478?.recommended, '16.1.0-canary.12');
      assert.strictEqual(patch55184?.recommended, '16.1.0-canary.18');
      assert.strictEqual(patch55183?.recommended, '16.1.0-canary.18');
    });
  });
});
