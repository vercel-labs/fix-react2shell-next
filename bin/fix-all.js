#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { run, analyzePackageJson } = require('../lib/index.js');

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

function findDirsWithPackageJson(dir, results = []) {
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    results.push(dir);
  }

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return results;
  }

  for (const entry of entries) {
    if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      findDirsWithPackageJson(path.join(dir, entry.name), results);
    }
  }

  return results;
}

async function main() {
  const startDir = process.cwd();
  const dirs = findDirsWithPackageJson(startDir);

  if (dirs.length === 0) {
    console.log('No package.json files found.');
    return;
  }

  console.log(`\n📂 Exploring ${dirs.length} directory(ies) with package.json:\n`);
  for (const dir of dirs) {
    const relative = path.relative(startDir, dir) || '.';
    console.log(`   ${relative}`);
  }

  const explored = [];
  const fixed = [];
  const errors = [];

  for (const dir of dirs) {
    const relative = path.relative(startDir, dir) || '.';
    const pkgPath = path.join(dir, 'package.json');

    console.log(`\n${'='.repeat(60)}`);
    console.log(`Running in: ${relative}`);
    console.log('='.repeat(60));

    const analysisBefore = analyzePackageJson(pkgPath);
    const hadVulnerabilities = analysisBefore && analysisBefore.vulnerabilities.length > 0;

    explored.push({ dir: relative, hadVulnerabilities });

    process.chdir(dir);

    try {
      await run();

      if (hadVulnerabilities) {
        const analysisAfter = analyzePackageJson(pkgPath);
        const stillVulnerable = analysisAfter && analysisAfter.vulnerabilities.length > 0;
        if (!stillVulnerable) {
          fixed.push(relative);
        }
      }
    } catch (err) {
      console.error(`Error in ${relative}:`, err.message);
      errors.push({ dir: relative, error: err.message });
    }
  }

  process.chdir(startDir);

  console.log(`\n${'='.repeat(60)}`);
  console.log('SUMMARY');
  console.log('='.repeat(60));

  console.log(`\n📂 Directories explored (${explored.length}):`);
  for (const { dir, hadVulnerabilities } of explored) {
    const status = hadVulnerabilities ? '⚠️  vulnerable' : '✓ clean';
    console.log(`   ${dir} - ${status}`);
  }

  if (fixed.length > 0) {
    console.log(`\n✅ Directories fixed (${fixed.length}):`);
    for (const dir of fixed) {
      console.log(`   ${dir}`);
    }
  }

  if (errors.length > 0) {
    console.log(`\n❌ Errors (${errors.length}):`);
    for (const { dir, error } of errors) {
      console.log(`   ${dir}: ${error}`);
    }
  }

  console.log();
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
