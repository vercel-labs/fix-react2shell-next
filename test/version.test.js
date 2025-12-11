/**
 * Tests for version utility functions
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  getVersionPrefix,
  applyVersionPrefix,
  hasUnsupportedRange,
  cleanVersion,
} = require('../lib/utils/version');

describe('getVersionPrefix', () => {
  it('should extract ^ prefix', () => {
    assert.strictEqual(getVersionPrefix('^15.3.0'), '^');
  });

  it('should extract ~ prefix', () => {
    assert.strictEqual(getVersionPrefix('~15.3.0'), '~');
  });

  it('should extract >= prefix', () => {
    assert.strictEqual(getVersionPrefix('>=15.3.0'), '>=');
  });

  it('should extract > prefix', () => {
    assert.strictEqual(getVersionPrefix('>15.3.0'), '>');
  });

  it('should NOT extract < prefix (unsupported)', () => {
    assert.strictEqual(getVersionPrefix('<16.0.0'), '');
  });

  it('should NOT extract <= prefix (unsupported)', () => {
    assert.strictEqual(getVersionPrefix('<=16.0.0'), '');
  });

  it('should return empty string for exact versions', () => {
    assert.strictEqual(getVersionPrefix('15.3.0'), '');
  });

  it('should return empty string for null', () => {
    assert.strictEqual(getVersionPrefix(null), '');
  });

  it('should return empty string for undefined', () => {
    assert.strictEqual(getVersionPrefix(undefined), '');
  });

  it('should handle canary versions with prefix', () => {
    assert.strictEqual(getVersionPrefix('^15.6.0-canary.58'), '^');
  });
});

describe('hasUnsupportedRange', () => {
  describe('supported ranges', () => {
    it('should accept exact versions', () => {
      assert.strictEqual(hasUnsupportedRange('15.3.0').unsupported, false);
    });

    it('should accept ^ prefix', () => {
      assert.strictEqual(hasUnsupportedRange('^15.3.0').unsupported, false);
    });

    it('should accept ~ prefix', () => {
      assert.strictEqual(hasUnsupportedRange('~15.3.0').unsupported, false);
    });

    it('should accept >= prefix', () => {
      assert.strictEqual(hasUnsupportedRange('>=15.3.0').unsupported, false);
    });

    it('should accept > prefix', () => {
      assert.strictEqual(hasUnsupportedRange('>15.3.0').unsupported, false);
    });
  });

  describe('unsupported ranges', () => {
    it('should reject < prefix', () => {
      const result = hasUnsupportedRange('<16.0.0');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'less-than-range');
    });

    it('should reject <= prefix', () => {
      const result = hasUnsupportedRange('<=16.0.0');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'less-than-range');
    });

    it('should reject hyphen ranges', () => {
      const result = hasUnsupportedRange('15.0.0 - 16.0.0');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'hyphen-range');
    });

    it('should reject OR ranges', () => {
      const result = hasUnsupportedRange('^15.0.0 || ^16.0.0');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'or-range');
    });

    it('should reject x-ranges (15.x)', () => {
      const result = hasUnsupportedRange('15.x');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'x-range');
    });

    it('should reject x-ranges (15.3.x)', () => {
      const result = hasUnsupportedRange('15.3.x');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'x-range');
    });

    it('should reject star ranges (15.*)', () => {
      const result = hasUnsupportedRange('15.*');
      assert.strictEqual(result.unsupported, true);
      assert.strictEqual(result.reason, 'x-range');
    });
  });
});

describe('applyVersionPrefix', () => {
  describe('supported prefixes', () => {
    it('should preserve ^ prefix', () => {
      assert.strictEqual(applyVersionPrefix('^15.3.0', '15.3.7'), '^15.3.7');
    });

    it('should preserve ~ prefix', () => {
      assert.strictEqual(applyVersionPrefix('~15.3.0', '15.3.7'), '~15.3.7');
    });

    it('should preserve >= prefix', () => {
      assert.strictEqual(applyVersionPrefix('>=15.3.0', '15.3.7'), '>=15.3.7');
    });

    it('should preserve > prefix', () => {
      assert.strictEqual(applyVersionPrefix('>15.3.0', '15.3.7'), '>15.3.7');
    });

    it('should keep exact version when no prefix', () => {
      assert.strictEqual(applyVersionPrefix('15.3.0', '15.3.7'), '15.3.7');
    });

    it('should handle canary versions', () => {
      assert.strictEqual(applyVersionPrefix('^15.6.0-canary.50', '15.6.0-canary.59'), '^15.6.0-canary.59');
    });

    it('should handle upgrading from stable to canary with prefix', () => {
      assert.strictEqual(applyVersionPrefix('^15.5.0', '15.6.0-canary.59'), '^15.6.0-canary.59');
    });
  });

  describe('unsupported ranges fall back to exact version', () => {
    it('should pin exact for < prefix', () => {
      assert.strictEqual(applyVersionPrefix('<16.0.0', '15.3.7'), '15.3.7');
    });

    it('should pin exact for <= prefix', () => {
      assert.strictEqual(applyVersionPrefix('<=16.0.0', '15.3.7'), '15.3.7');
    });

    it('should pin exact for hyphen ranges', () => {
      assert.strictEqual(applyVersionPrefix('15.0.0 - 16.0.0', '15.3.7'), '15.3.7');
    });

    it('should pin exact for OR ranges', () => {
      assert.strictEqual(applyVersionPrefix('^15.0.0 || ^16.0.0', '15.3.7'), '15.3.7');
    });

    it('should pin exact for x-ranges', () => {
      assert.strictEqual(applyVersionPrefix('15.x', '15.3.7'), '15.3.7');
    });
  });
});

describe('cleanVersion', () => {
  it('should remove ^ prefix', () => {
    assert.strictEqual(cleanVersion('^15.3.0'), '15.3.0');
  });

  it('should remove ~ prefix', () => {
    assert.strictEqual(cleanVersion('~15.3.0'), '15.3.0');
  });

  it('should remove >= prefix', () => {
    assert.strictEqual(cleanVersion('>=15.3.0'), '15.3.0');
  });

  it('should keep exact versions unchanged', () => {
    assert.strictEqual(cleanVersion('15.3.0'), '15.3.0');
  });
});
