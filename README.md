# fix-react2shell-next

![fix-react2shell-next](https://raw.githubusercontent.com/vercel-labs/fix-react2shell-next/main/cli.gif)

One command to fix multiple React/Next.js security vulnerabilities in your Next.js / React RSC app.

```bash
npx fix-react2shell-next
```

Deterministic version bumps per the official advisories.

## What it does

1. **Recursively scans** all `package.json` files (handles monorepos)
2. **Checks** for vulnerable versions of:
   - `next`
   - `react-server-dom-webpack`
   - `react-server-dom-parcel`
   - `react-server-dom-turbopack`
3. **Patches** to the correct fixed version based on your current version
4. **Refreshes** your lockfile with the detected package manager

## Affected Versions

### Next.js

| Current Version | Patched Version |
|-----------------|-----------------|
| 15.0.0 – 15.0.4 | 15.0.5 |
| 15.1.0 – 15.1.8 | 15.1.9 |
| 15.2.0 – 15.2.5 | 15.2.6 |
| 15.3.0 – 15.3.5 | 15.3.6 |
| 15.4.0 – 15.4.7 | 15.4.8 |
| 15.5.0 – 15.5.6 | 15.5.7 |
| 16.0.0 – 16.0.6 | 16.0.7 |
| 15.x canaries | 15.6.0-canary.58 |
| 16.x canaries | 16.1.0-canary.12 |
| 14.3.0-canary.77+ | Downgrade to 14.3.0-canary.76 or upgrade to 15.0.5 |

### React Packages (CVE-2025-55182)

| Current Version | Patched Version |
|-----------------|-----------------|
| 19.0.0 | 19.0.1 |
| 19.1.0, 19.1.1 | 19.1.2 |
| 19.2.0 | 19.2.1 |

*Applies to: `react`, `react-dom`, `react-server-dom-webpack`, `react-server-dom-parcel`, `react-server-dom-turbopack`*

## Usage

### Check & Fix (Interactive)

```bash
npx fix-react2shell-next
```

### Auto-fix (CI / Non-interactive)

```bash
npx fix-react2shell-next --fix
```

### Check Only (Dry Run)

```bash
npx fix-react2shell-next --dry-run
```

### JSON Output (for scripting)

```bash
npx fix-react2shell-next --json
```

## Example Output

```
🔍 fix-react2shell-next - CVE-2025-66478 vulnerability scanner

📂 Found 3 package.json file(s)

🚨 Found 2 vulnerable file(s):

  📄 package.json
     next: ^15.1.0 → 15.1.9

  📄 apps/web/package.json
     next: ^15.4.3 → 15.4.8
     react-server-dom-webpack: 19.1.0 → 19.1.2

🔧 Apply fixes? [Y/n] y

🔧 Applying fixes...

   ✓ Updated package.json
   ✓ Updated apps/web/package.json

📦 Package manager: pnpm
🔄 Refreshing lockfile...

$ pnpm install

✅ Patches applied!
   Remember to test your app and commit the changes.
```

## Monorepo Support

The tool automatically finds all `package.json` files in your project, excluding:
- `node_modules`
- `.next`, `.turbo`, `.vercel`, `.nuxt`
- `dist`, `build`, `.output`
- `coverage`

Works with npm, yarn, pnpm, and bun workspaces.

## References

- [GitHub Advisory GHSA-9qr9-h5gf-34mp](https://github.com/advisories/GHSA-9qr9-h5gf-34mp)
- [Next.js Security Advisory](https://nextjs.org/blog/CVE-2025-66478)
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)

## License

MIT
