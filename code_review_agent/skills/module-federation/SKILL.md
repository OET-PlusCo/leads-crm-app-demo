---
name: module-federation
description: >-
  Reviews Module Federation configuration and usage patterns.
  Use when reviewing vite.config.ts, host/remote setup, shared dependency
  config, exposes/remotes declarations, or cross-app integration code.
  Covers @module-federation/vite and Webpack MF v2. Catches singleton misuse,
  version mismatches in shared deps, missing eager loading, unsafe dynamic
  imports, and broken remote contracts.
---

# Module Federation Review Skill

## Scope

Apply this skill when the diff touches:
- `vite.config.ts` / `webpack.config.js` containing `federation()` or `ModuleFederationPlugin`
- Files in `exposes` paths (modules exported to other apps)
- Files that use `import()` with remote app names
- `remotes` declarations
- Bootstrap files (`bootstrap.ts`, `main.ts`) in federated apps
- `package.json` changes affecting shared dependency versions

---

## 1. Shared Dependencies (`shared:`)

This is the #1 source of MF bugs. Review every `shared` entry carefully.

### Critical checks

**Singleton misuse**
```ts
// BAD — React loaded twice, hooks will break across boundaries
shared: { react: { requiredVersion: '^19.0.0' } }  // missing singleton: true

// GOOD
shared: {
  react: { singleton: true, requiredVersion: '^19.0.0' },
  'react-dom': { singleton: true, requiredVersion: '^19.0.0' },
}
```
Flag as 🔴 CRITICAL if `react`, `react-dom`, or any context-based library (`zustand`, `@tanstack/react-query`, `react-router-dom`) is shared without `singleton: true`.

**Version mismatches across apps**
If host declares `requiredVersion: '^19.0.0'` but a remote uses `^18.0.0`, the mismatch causes a runtime warning and may silently load both. Flag as 🟠 HIGH when shared dep versions across `vite.config.ts` files differ.

**Eager loading in shell/host**
The host's bootstrap must be async to allow federation to initialise before app code runs:
```ts
// bootstrap.ts (host)
import('./app');  // GOOD — async bootstrap

// main.ts (host) — BAD, imports app synchronously before MF is ready
import App from './App';
```
Flag as 🔴 CRITICAL if host has no async bootstrap file.

**Missing `strictVersion`**
When a shared dep is version-sensitive (e.g. a design system), missing `strictVersion: true` lets incompatible versions load silently:
```ts
// Flag if a shared internal package lacks strictVersion
'@pluscompany/ui': { singleton: true, strictVersion: true }
```

---

## 2. `exposes` — Remote Contract Review

Every exposed module is a **public API contract**. Breaking changes affect all consumers.

### Checks
- **Default export present**: All exposed modules must have a default export. Named-only exports require consumers to update imports.
- **No internal/private imports in exposed files**: Exposed modules must not import from `../internal/` or similar private paths — these become transitive dependencies for the host.
- **TypeScript types exported**: If the project uses TypeScript, exposed modules should export their prop/return types so host apps get type safety.
- **Consistent module path**: Changing the key in `exposes` (e.g. `./Button` → `./components/Button`) is a breaking change — flag as 🟠 HIGH.

```ts
// BAD — exposes internal impl detail
exposes: {
  './AuthContext': './src/internal/auth/context.ts',  // internal path exposed
}

// GOOD
exposes: {
  './AuthContext': './src/auth/index.ts',  // public entry point
}
```

---

## 3. `remotes` — Host Configuration

```ts
// BAD — hardcoded localhost URL, will break in CI/prod
remotes: {
  shell: 'shell@http://localhost:3000/remoteEntry.js',
}

// GOOD — environment-driven remote URL
remotes: {
  shell: `shell@${process.env.SHELL_URL ?? 'http://localhost:3000'}/remoteEntry.js`,
}
```

Flag as 🟠 HIGH any hardcoded `localhost` in remote URLs outside of dev-only config.

**Dynamic remotes**: If remotes are loaded dynamically at runtime (`__webpack_init_sharing__`, `loadRemote()`), verify error boundaries wrap the dynamic import — a failed remote load must not crash the host.

---

## 4. `@module-federation/vite` Specific Patterns

**Plugin order**: The MF plugin must come before other Vite plugins that transform entry points:
```ts
// GOOD
plugins: [federation({ ... }), react()]

// BAD — react plugin before federation may transform bootstrap before MF init
plugins: [react(), federation({ ... })]
```

**`filename` option**: The remote entry file name must match what the host's `remotes` URL expects:
```ts
// Remote vite.config.ts
federation({ filename: 'remoteEntry.js', ... })
// Host must reference: 'remote@http://host/remoteEntry.js' — check alignment
```

**`dev` mode remotes**: In dev, `@module-federation/vite` serves a dev manifest. Verify the dev server port in `remotes` matches the remote app's `server.port`.

---

## 5. Integration & Runtime Patterns

**Error boundaries around remote components**
Every component loaded from a remote must be wrapped in an error boundary and `React.Suspense`:
```tsx
// BAD — no error handling for remote load failure
const RemoteButton = React.lazy(() => import('ui/Button'));

// GOOD
<ErrorBoundary fallback={<FallbackUI />}>
  <Suspense fallback={<Spinner />}>
    <RemoteButton />
  </Suspense>
</ErrorBoundary>
```
Flag as 🟠 HIGH if lazy remote imports lack Suspense+ErrorBoundary.

**Shared state across boundaries**
State passed from host to remote must go through shared singletons (React Context with `singleton: true`, or a shared store). Never pass state via window globals.

---

## 6. Security Considerations

- **Remote URL injection**: If remote URLs come from user input or unvalidated config, flag as 🔴 CRITICAL (arbitrary code execution risk).
- **Exposed modules leaking auth tokens**: Verify exposed modules do not re-export anything that includes API keys, tokens, or secrets from env vars at build time.
- **CSP headers**: Federated apps loading remotes from external domains require `script-src` CSP entries — flag missing CSP config as 🟡 MEDIUM.

---

## Severity Reference

| Issue | Severity |
|---|---|
| `singleton: true` missing on React/context libs | 🔴 CRITICAL |
| No async bootstrap in host app | 🔴 CRITICAL |
| Remote URL from unvalidated input | 🔴 CRITICAL |
| Hardcoded localhost in remote URLs | 🟠 HIGH |
| Exposed module breaking change (key rename/removal) | 🟠 HIGH |
| Remote dynamic import without error boundary | 🟠 HIGH |
| Version mismatch in shared deps across apps | 🟠 HIGH |
| Missing `strictVersion` on internal shared packages | 🟡 MEDIUM |
| Wrong Vite plugin order | 🟡 MEDIUM |
| Missing CSP for cross-origin remotes | 🟡 MEDIUM |
| Exposed module imports from internal paths | 🟡 MEDIUM |
