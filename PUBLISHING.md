# Publishing to npm

Package: **`@elephantseed/auto-bumper`** — [elephantseed org](https://www.npmjs.com/org/elephantseed)

Published under the **elephantseed** npm organization. Public package — free, no paid plan needed.

`publishConfig.access` is `public` so anyone can install without npm login.

## Prerequisites

1. Logged in as your npm user (org member with publish rights)
2. [Bun](https://bun.sh) >= 1.0
3. Git repo on GitHub (recommended)

## One-time setup

### 1. Log in to npm

```powershell
npm login
npm whoami
# should print your npm username
npm org ls elephantseed
```

### 2. Repository metadata (optional)

Add to `package.json` when you have a GitHub repo:

```json
"repository": {
  "type": "git",
  "url": "git+https://github.com/sloppylopez/auto-bumper.git"
},
"bugs": {
  "url": "https://github.com/sloppylopez/auto-bumper/issues"
},
"homepage": "https://github.com/sloppylopez/auto-bumper#readme",
```

### 3. Dry-run

```powershell
npm pack --dry-run
```

Only `cli/`, `src/`, `local-advisories/`, `README.md`, `LICENSE`, and `package.json` should appear — anything else (`.env`, node_modules, test fixtures) is a mistake.

## Publish

```powershell
npm version patch
npm publish
```

`--access public` not needed — already in `package.json` `publishConfig`.

`prepublishOnly` runs typecheck first.

Tag on GitHub:

```powershell
git push origin main --tags
```

## Verify install

```powershell
bunx --package @elephantseed/auto-bumper scan -- C:\path\to\project
bunx --package @elephantseed/auto-bumper fix -- C:\path\to\project --dry-run
bunx --package @elephantseed/auto-bumper update-db
```

Or:

```powershell
bun add @elephantseed/auto-bumper
bunx --package @elephantseed/auto-bumper scan -- .
```

## Deprecate (not unpublish)

```powershell
npm deprecate @elephantseed/auto-bumper@0.1.0 "use 0.1.1 instead"
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| `403 Forbidden` | confirm org publish rights: `npm org ls elephantseed` |
| version already exists | `npm version patch` |
| CLI fails globally | use `bunx --package @elephantseed/auto-bumper scan` |

## CI (optional)

```yaml
- run: npm publish
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Run on version tags only. Token needs publish rights for `@elephantseed`.
