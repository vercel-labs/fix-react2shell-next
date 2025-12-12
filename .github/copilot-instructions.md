<!-- Copilot instructions for fix-react2shell-next -->
# fix-react2shell-next — Copilot Instructions

Purpose: help AI coding agents be productive quickly when editing or extending this CLI security tool.

- Quick entry points:
  - CLI runner: `bin/cli.js` (calls `run()` in `lib/index.js`).
  - Core logic: `lib/index.js` — contains scanning, detection, patching, and install logic.
  - Documentation & examples: `README.md` (usage and examples).

- Big picture / architecture:
  - Single-purpose CLI that recursively scans `package.json` files, detects vulnerable `next` and React RSC packages, writes patched versions, and refreshes lockfiles.
  - Monorepo aware: detects workspaces (`pnpm-workspace.yaml` or `package.json.workspaces`) and prefers running installs at monorepo root.
  - Package-manager integration: calls `pnpm`, `npm`, `yarn`, `bun` via `child_process.spawnSync` (10s timeouts).

- Critical code patterns to preserve or follow:
  - Vulnerability detection uses `isNextVersionVulnerable()` and `isReactRscVersionVulnerable()` — change these only with tests and matching advisory data.
  - `findAllPackageJsons()` skips directories in `SKIP_DIRS` — update that set if adding new build folders.
  - When applying fixes, the code pins exact versions (no `^`) and writes JSON with 2-space formatting.
  - CLI supports `--fix`, `--dry-run`, and `--json` flags; maintain the JSON output shape for automation consumers.

- Developer workflows / commands:
  - Local run: `node bin/cli.js` (or `npx fix-react2shell-next`).
  - Dry-run: `node bin/cli.js --dry-run`.
  - CI / non-interactive: `node bin/cli.js --fix --json`.
  - Release flow: uses `changeset` scripts defined in `package.json` (`pnpm` recommended per `packageManager` field).

- Project-specific conventions:
  - Prefer synchronous, simple CLI behavior (uses `spawnSync` and immediate stdout/stderr handling).
  - Timeouts and fallbacks for package-manager queries are intentional — avoid long-running async replacements without preserving timeouts.
  - JSON machine-output is the contract for automation (`--json` prints an object with `vulnerable`, `count`, `files`).

- Integration points & tests to simulate:
  - To emulate package manager responses, create a temporary folder with a lockfile (`pnpm-lock.yaml`, `yarn.lock`, etc.) so `detectPackageManager()` returns expected value.
  - `getInstalledVersionFromPackageManager()` parses CLI output for each PM; when modifying, preserve parsing logic or add robust unit tests.

- Quick inspection pointers (files to open first):
  - `.github/copilot-instructions.md` (this file)
  - `lib/index.js` — core functions: `run()`, `findAllPackageJsons()`, `analyzePackageJson()`, `applyFixes()` and version helpers like `getNextPatchedVersion()`.
  - `bin/cli.js` — entry shim.
  - `README.md` — expected CLI behavior and examples.

- When making changes, be conservative:
  - Preserve CLI flags and JSON contract.
  - Keep `SKIP_DIRS` behavior and workspace detection intact unless explicitly expanding supported workspace types.
  - Add unit tests (or reproducible examples) when changing version-parsing or package-manager parsing logic.

- If anything here is unclear or you want the instructions in Arabic or expanded with concrete code snippets/tests, tell me which sections to expand.
