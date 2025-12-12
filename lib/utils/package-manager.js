const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { c } = require('./colors');

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function detectPackageManager(startDir) {
  let dir = startDir;

  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, 'bun.lockb')) || fs.existsSync(path.join(dir, 'bun.lock'))) {
      return 'bun';
    }
    if (fs.existsSync(path.join(dir, 'pnpm-lock.yaml'))) {
      return 'pnpm';
    }
    if (fs.existsSync(path.join(dir, 'yarn.lock'))) {
      return 'yarn';
    }
    if (fs.existsSync(path.join(dir, 'package-lock.json'))) {
      return 'npm';
    }
    dir = path.dirname(dir);
  }

  return 'npm';
}

function getInstalledVersionFromNodeModules(pkgDir, packageName) {
  const nodeModulesPath = path.join(pkgDir, 'node_modules', packageName, 'package.json');
  try {
    const pkg = JSON.parse(fs.readFileSync(nodeModulesPath, 'utf8'));
    return pkg.version;
  } catch (e) {
    return null;
  }
}

function getInstalledVersionFromPackageManager(pkgDir, packageName, packageManager) {
  const pm = packageManager || detectPackageManager(pkgDir);
  if (!pm) return null;

  try {
    let result;

    switch (pm) {
      case 'pnpm': {
        result = spawnSync('pnpm', ['why', packageName, '--json'], {
          cwd: pkgDir,
          encoding: 'utf8',
          shell: process.platform === 'win32',
          timeout: 10000,
        });

        if (result.status === 0 && result.stdout) {
          try {
            const data = JSON.parse(result.stdout);
            if (Array.isArray(data)) {
              for (const entry of data) {
                if (entry.dependencies) {
                  const dep = entry.dependencies[packageName];
                  if (dep && dep.version) {
                    return dep.version;
                  }
                }
              }
            }
          } catch (e) {
            // JSON parse failed, try alternative
          }
        }

        result = spawnSync('pnpm', ['list', packageName, '--json', '--depth=0'], {
          cwd: pkgDir,
          encoding: 'utf8',
          shell: process.platform === 'win32',
          timeout: 10000,
        });

        if (result.status === 0 && result.stdout) {
          try {
            const data = JSON.parse(result.stdout);
            const entry = Array.isArray(data) ? data[0] : data;
            if (entry?.dependencies?.[packageName]?.version) {
              return entry.dependencies[packageName].version;
            }
            if (entry?.devDependencies?.[packageName]?.version) {
              return entry.devDependencies[packageName].version;
            }
          } catch (e) {
            // Continue to fallback
          }
        }
        break;
      }

      case 'npm': {
        result = spawnSync('npm', ['ls', packageName, '--json', '--depth=0'], {
          cwd: pkgDir,
          encoding: 'utf8',
          shell: process.platform === 'win32',
          timeout: 10000,
        });

        if (result.status === 0 && result.stdout) {
          try {
            const data = JSON.parse(result.stdout);
            if (data.dependencies?.[packageName]?.version) {
              return data.dependencies[packageName].version;
            }
            if (data.devDependencies?.[packageName]?.version) {
              return data.devDependencies[packageName].version;
            }
          } catch (e) {
            // Continue to fallback
          }
        }
        break;
      }

      case 'yarn': {
        result = spawnSync('yarn', ['list', '--pattern', packageName, '--json', '--depth=0'], {
          cwd: pkgDir,
          encoding: 'utf8',
          shell: process.platform === 'win32',
          timeout: 10000,
        });

        if (result.status === 0 && result.stdout) {
          const lines = result.stdout.trim().split('\n');
          for (const line of lines) {
            try {
              const data = JSON.parse(line);
              if (data.type === 'tree' && data.data?.trees) {
                for (const tree of data.data.trees) {
                  const match = tree.name?.match(new RegExp(`^${escapeRegExp(packageName)}@(.+)$`));
                  if (match) {
                    return match[1];
                  }
                }
              }
            } catch (e) {
              // Continue parsing
            }
          }
        }
        break;
      }

      case 'bun': {
        result = spawnSync('bun', ['pm', 'ls'], {
          cwd: pkgDir,
          encoding: 'utf8',
          shell: process.platform === 'win32',
          timeout: 10000,
        });

        if (result.status === 0 && result.stdout) {
          const lines = result.stdout.split('\n');
          for (const line of lines) {
            const match = line.match(new RegExp(`${escapeRegExp(packageName)}@(\\d+\\.\\d+\\.\\d+[^\\s]*)`));
            if (match) {
              return match[1];
            }
          }
        }
        break;
      }
    }
  } catch (e) {
    // Package manager command failed, return null
  }

  return null;
}

function getInstalledVersion(pkgDir, packageName) {
  // Try package manager first (handles catalogs, overrides, hoisting, etc.)
  const pmVersion = getInstalledVersionFromPackageManager(pkgDir, packageName);
  if (pmVersion) return pmVersion;

  // Fall back to reading node_modules directly
  return getInstalledVersionFromNodeModules(pkgDir, packageName);
}

function getYarnMajorVersion(cwd) {
  try {
    const result = spawnSync('yarn', ['--version'], {
      cwd,
      encoding: 'utf8',
      shell: process.platform === 'win32',
      timeout: 5000,
    });
    if (result.status === 0 && result.stdout) {
      return parseInt(result.stdout.trim().split('.')[0], 10);
    }
  } catch (e) {
    // Fall through
  }
  return 1;
}

function runInstall(packageManager, cwd, { lockfileOnly = false } = {}) {
  let commands;

  if (lockfileOnly) {
    commands = {
      npm: ['npm', ['install', '--package-lock-only']],
      yarn: ['yarn', getYarnMajorVersion(cwd) >= 2 ? ['install', '--mode', 'update-lockfile'] : ['install']],
      pnpm: ['pnpm', ['install', '--lockfile-only']],
      bun: ['bun', ['install', '--lockfile-only']],
    };
  } else {
    commands = {
      npm: ['npm', ['install']],
      yarn: ['yarn', ['install']],
      pnpm: ['pnpm', ['install']],
      bun: ['bun', ['install']],
    };
  }

  const [cmd, args] = commands[packageManager] || commands.npm;

  console.log(c('dim', `\n$ ${cmd} ${args.join(' ')}\n`));

  const result = spawnSync(cmd, args, {
    cwd,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  return result.status === 0;
}

function getInstallCommand(packageManager) {
  switch (packageManager) {
    case 'bun': return 'bun install';
    case 'pnpm': return 'pnpm install';
    case 'yarn': return 'yarn install';
    default: return 'npm install';
  }
}

module.exports = {
  detectPackageManager,
  getInstalledVersion,
  getInstalledVersionFromPackageManager,
  getInstalledVersionFromNodeModules,
  runInstall,
  getInstallCommand,
};
