# Security Hardening - Implementation Plan

- [x] 1. Add configuration module with fail-fast validation
  - Create `src/config.ts` exporting `WPConfig` and `loadConfig()`.
  - Read `WP_SITE_URL`, `WP_USERNAME`, `WP_APP_PASSWORD`, plus toggles
    `WP_ALLOW_INSECURE_HTTP`, `WP_ALLOW_PRIVATE_HOSTS`, `WP_ALLOW_DESTRUCTIVE`, and
    `WP_ALLOWED_HOSTS` (comma-separated). Support optional JSON file via `WP_MCP_CONFIG`.
  - Validate with zod; throw a descriptive error naming missing keys (never values).
  - _Requirements: 1.1, 1.3, 2.2, 3.4, 6.1_

- [x] 2. Implement target validation / SSRF guard
  - Add `validateTarget(url, config)` in `src/config.ts` (or a `src/security.ts`).
  - Enforce `https:` unless `allowInsecureHttp` and loopback host.
  - Block private, loopback, link-local, and unique-local IP ranges (incl.
    `169.254.169.254`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `::1`,
    `fc00::/7`, `fe80::/10`) unless `allowPrivateHosts`.
  - Enforce `allowedHosts` membership when configured.
  - _Requirements: 2.1, 2.3, 3.2, 3.4_

- [x] 3. Refactor `makeWPRequest` to use config and the SSRF guard
  - Remove `siteUrl` and `auth` parameters; read them from loaded config.
  - Call `validateTarget` before issuing the request.
  - Use a dedicated `axios.create({ maxRedirects: 0 })` instance; attach Basic auth only
    on the validated request, not as a global default.
  - _Requirements: 1.4, 2.1, 3.1, 3.3_

- [x] 4. Remove credentials and siteUrl from all tool schemas
  - Delete `siteUrl`, `username`, `password` from every tool's zod schema and handler
    destructuring across `src/index.ts`.
  - Update each `makeWPRequest` call site to the new signature.
  - Verify no tool still references the removed parameters.
  - _Requirements: 1.1, 1.2_

- [x] 5. Gate destructive tools behind `allowDestructive`
  - In `delete-user`, `delete-post` (force path), and `delete-category`, return a clear
    refusal when `config.allowDestructive` is false.
  - _Requirements: 6.1, 6.2_

- [x] 6. Harden error reporting
  - In `makeWPRequest`'s catch, return status + short upstream message only; never include
    URLs with query params, headers, or credentials; truncate long messages.
  - _Requirements: 7.1, 7.2_

- [x] 7. Update dependencies and verify audit is clean
  - Resolved a duplicate `zod` install (project `3.24.3` + nested `4.4.3` under the SDK)
    that caused tsc to OOM via runaway type comparison; aligned the tree on a single
    `zod@4.4.3` and migrated the v4 breaking changes (`required_error` -> `error`,
    `z.record(z.string(), z.any())`, `McpServer` capabilities moved to options arg).
  - Left `axios` and `@modelcontextprotocol/sdk` as-is since `npm audit` is already clean.
  - Confirmed `npm audit` reports zero vulnerabilities and `npm run build` succeeds (exit 0).
  - _Requirements: 4.1, 4.2, 4.3_

- [ ] 8. Add focused tests for security-critical units
  - Set up a test runner (vitest or node:test).
  - Test `validateTarget` (scheme, private-range, allowlist cases) and `loadConfig`
    (missing keys, boolean/list parsing) and destructive gating.
  - _Requirements: 2.1, 2.2, 3.2, 3.4, 1.3, 6.1_

- [ ] 9. Align README with the implementation
  - Rewrite the tool list to match the actual kebab-case tools; remove non-existent tools
    (`custom_request`, `get_user_by_login`, etc.).
  - Document environment-variable configuration and the security toggles, replacing
    per-call credential examples.
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 10. Final verification pass
  - Run `npm run build`, `npm audit`, and the new tests.
  - Confirm the server fails fast without required env vars and starts with them.
  - _Requirements: 1.3, 4.1, 4.3_
