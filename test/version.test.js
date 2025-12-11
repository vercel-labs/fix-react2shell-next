/**
 * Tests for version utility functions
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  getVersionPrefix,
  applyVersionPrefix,
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

  it('should extract < prefix', () => {
    assert.strictEqual(getVersionPrefix('<16.0.0'), '<');
  });

  it('should extract <= prefix', () => {
    assert.strictEqual(getVersionPrefix('<=16.0.0'), '<=');
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

describe('applyVersionPrefix', () => {
  it('should preserve ^ prefix', () => {
    assert.strictEqual(applyVersionPrefix('^15.3.0', '15.3.7'), '^15.3.7');
  });

  it('should preserve ~ prefix', () => {
    assert.strictEqual(applyVersionPrefix('~15.3.0', '15.3.7'), '~15.3.7');
  });

  it('should preserve >= prefix', () => {
    assert.strictEqual(applyVersionPrefix('>=15.3.0', '15.3.7'), '>=15.3.7');
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
