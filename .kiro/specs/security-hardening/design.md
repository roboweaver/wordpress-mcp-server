# Security Hardening - Design

## Context

The server is a single-file MCP server (`src/index.ts`, ~2100 lines) built on
`@modelcontextprotocol/sdk` over stdio, using `axios` for WordPress REST calls. Every
tool currently accepts `siteUrl`, `username`, and `password` as parameters and calls a
shared `makeWPRequest` helper:

```ts
async function makeWPRequest<T>({ siteUrl, endpoint, method, auth, data, params }) {
  const authString = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
  const response = await axios({
    method,
    url: `${siteUrl}/wp-json/wp/v2/${endpoint}`,
    headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
    data, params,
  });
  return response.data as T;
}
```

The design centralizes security controls in configuration loading and in `makeWPRequest`
so individual tool definitions change as little as possible.

## Goals

- Remove credentials and site URL from the model-visible tool surface.
- Enforce HTTPS and block SSRF targets at the single network choke point.
- Update dependencies to clear high/critical advisories.
- Keep tool behavior and names stable; align the README to reality.

## Authentication approach

This decision is grounded in the official WordPress documentation:
- [Authentication – REST API Handbook](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/)
- [Application Passwords – Advanced Administration Handbook](https://developer.wordpress.org/advanced-administration/security/application-passwords/)

WordPress core ships two first-party authentication methods. Cookie authentication is
the standard method but only works inside WordPress (same-domain, logged-in browser
session with a nonce), so it is not usable for an external MCP/automation client.
**Application Passwords** (introduced in WordPress 5.6) are the feature explicitly
designed for programmatic REST API access: per-application, revocable credentials, stored
hashed, shown once, tied to a user, and unusable for interactive wp-admin login. They are
sent via HTTP Basic Auth, and the documentation requires HTTPS because Basic Auth
credentials can otherwise be intercepted on the network.

JWT and OAuth are **not** WordPress core; they require third-party plugins and primarily
benefit multi-user/SaaS delegation scenarios. They add attack surface and maintenance
cost without improving security for a self-hosted site driven by a single local MCP
server. Critically, the authentication protocol is not where this server's risk lies: the
review findings (credentials flowing through the LLM context, missing HTTPS enforcement,
SSRF) are identical regardless of token type. The fix is in how the server handles the
secret and the transport, not in switching protocols.

**Decision:** use an **Application Password on a dedicated, least-privilege service user**,
supplied to the server out-of-band (Requirement 1) and sent only over HTTPS
(Requirement 2). Do not adopt JWT/OAuth unless the server is later exposed to multiple
users or external parties.

### Role / least-privilege guidance

The chosen WordPress role interacts with this server's toolset, and WordPress enforces
capability limits server-side regardless of what the model is prompted to do:
- Content tools (posts, comments, categories) work at the **Editor** level.
- `create-user`, `update-user`, `delete-user` require admin-level capabilities
  (`list_users`, `promote_users`, etc.).
- The Jetpack/WP.com **stats tools** require elevated privileges as well.

Recommendation: provision the service user with the **lowest role that covers the tools
actually in use**. For content-only workflows, Editor (or Author) is ideal and removes
the blast radius of the user-management and destructive user tools entirely. This
capability limit is a defense-in-depth feature, not a limitation to work around.

## Architecture

### 1. Configuration module

Add a small startup configuration loader (new file `src/config.ts`, imported by
`index.ts`).

Sources, in precedence order (later overrides earlier):
1. Environment variables.
2. Optional local config file path from `WP_MCP_CONFIG` (JSON), if present.

Configuration shape:

```ts
interface WPConfig {
  siteUrl: string;          // WP_SITE_URL, required, must be https unless dev override
  username: string;         // WP_USERNAME, required
  password: string;         // WP_APP_PASSWORD, required
  allowInsecureHttp: boolean; // WP_ALLOW_INSECURE_HTTP=true, default false (loopback only)
  allowPrivateHosts: boolean; // WP_ALLOW_PRIVATE_HOSTS=true, default false
  allowDestructive: boolean;  // WP_ALLOW_DESTRUCTIVE=true, default false
  allowedHosts?: string[];    // WP_ALLOWED_HOSTS comma-separated, optional allowlist
}
```

Behavior:
- `loadConfig()` validates with zod and throws a descriptive error if `siteUrl`,
  `username`, or `password` are missing or invalid.
- On validation failure, `main()` logs the error to stderr and calls `process.exit(1)`
  before connecting the transport (fail fast, addresses Req 1.3).
- The loaded config is never logged; only key names are referenced in errors.

### 2. Tool schema changes

Remove `siteUrl`, `username`, and `password` from every tool's zod schema and from each
handler's destructured arguments. Handlers call `makeWPRequest` without passing auth or
site URL; those come from the module-level config.

`makeWPRequest` signature becomes:

```ts
async function makeWPRequest<T>({ endpoint, method = 'GET', data = null, params = null }): Promise<T>
```

It reads `siteUrl` and credentials from the loaded config (captured in a closure or
imported singleton). This is a mechanical edit repeated across ~30 tools but keeps each
tool's domain parameters intact (postId, perPage, etc.).

This satisfies Req 1.1, 1.2, and Req 3.1 (site host fixed by config, not per call).

### 3. URL validation and SSRF guard

Add a `validateTarget(url: string, config: WPConfig)` helper used inside `makeWPRequest`
before any request:

1. Parse with the WHATWG `URL` constructor; reject unparseable URLs.
2. Scheme check: require `https:`. Allow `http:` only if `allowInsecureHttp` is true AND
   the host is a loopback address. (Req 2)
3. Host check: resolve whether the hostname is an IP literal in a private, loopback,
   link-local, or unique-local range; if so, block unless `allowPrivateHosts` is true.
   For DNS names, optionally resolve to IPs (via `dns.lookup`) and apply the same check to
   mitigate DNS-rebinding; at minimum block obvious literals like `169.254.169.254`,
   `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fc00::/7`,
   `fe80::/10`. (Req 3.2)
4. Allowlist: if `allowedHosts` is set, the host must be a member. (Req 3.4)

Because the site URL is fixed at config time, `validateTarget` primarily runs once per
process effectively, but it is enforced on every request to cover any future
endpoint-derived URLs.

### 4. Redirect handling

Configure the axios instance with `maxRedirects: 0` so the WordPress REST client does not
silently follow cross-host redirects that could leak the `Authorization` header. The WP
REST API for a correctly configured site does not require redirects for these endpoints.
If a redirect is encountered, surface it as an error rather than following it. (Req 3.3)

Use a single `axios.create({ maxRedirects: 0 })` instance rather than the global default,
and do not set credentials as defaults so they are only attached per validated request.

### 5. Dependency updates

Update `package.json`:
- `axios` to the latest 1.x that clears the listed advisories (and transitively pulls a
  fixed `form-data` and `follow-redirects`).
- `@modelcontextprotocol/sdk` to the latest release clearing the ReDoS and data-leak
  advisories.
- Run `npm audit fix` for transitive moderates (qs, body-parser, path-to-regexp) where a
  non-breaking fix exists.

Pin to explicit minimums and verify `npm run build` still succeeds and `npm audit` shows
zero high/critical. (Req 4)

Note: exact target versions are determined at implementation time by checking the current
published versions, since the advisory set evolves. The acceptance test is the audit
result, not a hardcoded version number.

#### Implementation outcome (zod major alignment)

During implementation, `npm run build` (tsc) crashed with a JavaScript heap out-of-memory
abort (`FATAL ERROR: Ineffective mark-compacts near heap limit`, exit 134) and no error
list. A `tsc --generateTrace` + `@typescript/analyze-trace` run identified the cause: a
**duplicate `zod` install**. The project pinned `zod@3.24.3`, but `@modelcontextprotocol/sdk`
declares `zod@^3.25 || ^4.0`; since `3.24.3` is just below `^3.25`, npm could not dedupe and
installed a second nested copy (`zod@4.4.3`) under the SDK. TypeScript then structurally
compared the project's zod-v3 schema types against the SDK's zod-v4 types across all ~29
`server.tool()` registrations, recursing through zod's deep generic types until it exhausted
the heap. The empty build output that earlier looked like a "hang" was this runaway
type-checking, not silent success (tsc is silent on success and exits 0).

Decision: align the entire tree on a single zod major. We chose **zod 4** (the latest, 4.4.3)
over pinning the 3.25.x line, because the SDK already uses zod 4 internally and zod 4 was
rewritten to reduce TypeScript checker load, lowering the chance of recurrence. The required
v4 migration was small and contained:
- `src/config.ts`: replace the removed `required_error` option with zod 4's unified `error`
  API (fail-fast messages that name each missing key were re-verified — Req 1.3).
- `src/index.ts`: `z.record(z.any())` -> `z.record(z.string(), z.any())` (v4 requires an
  explicit key schema) at the four `meta` fields.
- `src/index.ts`: move `capabilities` to the `McpServer` constructor's second options
  argument (an SDK-API mismatch that surfaced once the build type-checked past the OOM).

`axios@1.18.1` and `@modelcontextprotocol/sdk@1.29.0` were left in place because `npm audit`
already reports zero vulnerabilities with them; per the note above, the audit result is the
acceptance test. After alignment: single `zod@4.4.3`, `npm run build` exits 0, `npm audit`
reports 0 vulnerabilities.

### 6. Destructive operation gating

For `delete-user`, `delete-post` (force path), and `delete-category`:
- If `config.allowDestructive` is false, the tool returns a refusal message explaining how
  to enable destructive operations (set `WP_ALLOW_DESTRUCTIVE=true`).
- Keep the existing per-call `force` flags. (Req 6)

### 7. Error reporting

Update the catch block in `makeWPRequest`:
- Include HTTP status and the upstream `message` field only (already partially done), but
  truncate to a reasonable length and never include the request URL with query params or
  any header. (Req 7)

### 8. README alignment

Rewrite the README tool list to match the actual kebab-case tools in `src/index.ts`
(`get-users`, `get-user`, `create-user`, `update-user`, `delete-user`, `list-posts`,
`get-post`, `create-post`, `update-post`, `delete-post`, comment tools, stats tools,
category tools). Remove references to non-existent tools (`custom_request`,
`get_user_by_login`, etc.). Document the new environment-variable configuration and the
security toggles. (Req 5)

## Data flow (after changes)

```
startup: loadConfig() -> WPConfig (or exit 1)
              |
tool call (no creds in args) -> handler -> makeWPRequest({endpoint,...})
              |
        validateTarget(siteUrl, config)  // https + SSRF + allowlist
              |
        axios instance (maxRedirects:0, Basic auth attached here)
              |
        WordPress REST API
```

## Testing strategy

There is currently no test framework. Add a minimal one (the standard choice for a
TypeScript/Node ESM project, e.g. `vitest` or `node:test`) scoped to the security-critical
units:

1. `validateTarget`:
   - rejects `http://example.com` when `allowInsecureHttp` is false.
   - allows `http://127.0.0.1` only when `allowInsecureHttp` is true.
   - blocks `https://169.254.169.254`, `https://10.0.0.5`, `https://localhost` (resolving
     to loopback) unless `allowPrivateHosts` is true.
   - enforces `allowedHosts` membership when set.
2. `loadConfig`:
   - throws when `WP_SITE_URL`/`WP_USERNAME`/`WP_APP_PASSWORD` are missing.
   - parses booleans and the comma-separated allowlist correctly.
3. Destructive gating: delete tools refuse when `allowDestructive` is false.

Manual verification:
- `npm run build` compiles cleanly.
- `npm audit` reports zero high/critical.
- Server starts with valid env vars and refuses to start without them.

## Risks and tradeoffs

- Removing `siteUrl`/`username`/`password` from tool schemas is a breaking change to the
  tool interface. This is intentional and is the core security improvement; the README and
  any MCP client config must be updated accordingly.
- DNS-based SSRF protection is best-effort; full protection against DNS rebinding requires
  validating the IP actually connected to. Pinning the host via config and blocking
  private ranges covers the realistic threat for this tool.
- `maxRedirects: 0` could break against sites that redirect `http`->`https` at the REST
  layer; since we require `https` already, this is acceptable and safer.
