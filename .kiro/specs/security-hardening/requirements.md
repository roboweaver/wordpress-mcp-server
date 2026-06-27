# Security Hardening - Requirements

## Overview

This spec addresses security findings from a review of the WordPress MCP server
(`src/index.ts`). The server exposes WordPress REST API operations (posts, users,
comments, categories, stats) as MCP tools over stdio. The review found credential-handling
weaknesses, missing transport and SSRF protections, vulnerable dependencies, and
documentation drift.

The goal of this spec is to make the server safe to connect to a live WordPress site,
including production, without changing its core feature set.

## Full Security Analysis (review findings)

The following is the complete analysis that motivated this spec. Severities reflect
impact in the context of an MCP server that an LLM drives on the user's behalf.

### 1. Credentials passed as per-tool-call parameters - High

Every tool accepts `username` and `password` (a WordPress application password) as tool
arguments:

```ts
username: z.string().describe("WordPress username"),
password: z.string().describe("WordPress application password"),
```

Consequences:
- The application password flows through the LLM/MCP message context on every call.
- It can be captured in model-provider logs, chat history, and MCP transport logs.
- WordPress application passwords grant full REST API access for that user.

Desired outcome: credentials are supplied to the server out-of-band (environment
variables or a local config file) and never appear as model-visible tool input.

### 2. No HTTPS enforcement - High

`siteUrl` is validated only as a generic URL (`z.string().url()`), which accepts
`http://`. Authentication uses HTTP Basic:

```ts
const authString = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
// headers: { 'Authorization': `Basic ${authString}` }
```

Base64 is encoding, not encryption. Over `http://`, credentials travel in cleartext.
The README recommends HTTPS, but nothing enforces it.

Desired outcome: non-`https:` site URLs are rejected before any request is made
(with a narrowly scoped, opt-in exception for local development if needed).

### 3. SSRF / credential leakage to arbitrary hosts - High

`siteUrl` is fully caller/model-controllable and the server sends the `Authorization`
header to whatever host is supplied:

```ts
url: `${siteUrl}/wp-json/wp/v2/${endpoint}`
```

There is no host allowlist and no blocking of private, loopback, or link-local ranges
(`127.0.0.1`, `169.254.169.254`, `10.x`, `192.168.x`, etc.). A malicious prompt could
direct the server at an internal service or a cloud metadata endpoint, leaking the Basic
auth credentials to an attacker-controlled or internal host.

Desired outcome: the target host is validated against an allowlist and/or private and
loopback address ranges are blocked, and redirects do not silently retarget the
credentials.

### 4. Vulnerable dependencies - Critical / High

`npm audit` reports 7 vulnerabilities (1 critical, 3 high, 3 moderate):
- form-data (critical): unsafe multipart boundary generation and CRLF injection.
- axios `^1.8.4` (high): SSRF via NO_PROXY bypass, prototype-pollution gadgets enabling
  credential injection and request hijacking, cloud-metadata exfiltration, and DoS.
- @modelcontextprotocol/sdk (high): ReDoS and a cross-client data-leak advisory.
- Moderate issues in follow-redirects, qs, body-parser, path-to-regexp.

The axios SSRF and prototype-pollution issues compound finding #3.

Desired outcome: dependencies updated so `npm audit` reports no high or critical
vulnerabilities, with versions pinned to known-good releases.

### 5. README does not match the code - Trust / maintenance

The README documents tools that do not exist in `src/index.ts`, including a
`custom_request` tool that takes an arbitrary endpoint and HTTP method, plus
`get_user_by_login` and others. The actual code uses different kebab-case tool names and
has no arbitrary-request tool. This drift suggests the published artifact may differ from
the reviewed source. An arbitrary `custom_request` tool would significantly widen the
SSRF surface.

Desired outcome: documentation accurately reflects the tools actually implemented, and
any arbitrary-request capability is either absent or explicitly hardened.

### 6. Powerful destructive tools with no guardrails - Medium

`delete-user` (hardcoded `force: true` with post reassignment), `delete-post` (with
`force`), and `delete-category` are exposed directly to the model. A crafted or careless
prompt can permanently delete content.

Desired outcome: destructive operations are clearly identifiable and, where feasible,
gated behind an explicit opt-in so they are not invoked accidentally.

### 7. Error message passthrough - Low

Errors return the upstream API message to the caller:

```ts
throw new Error(`WordPress API error: ${error.response.data?.message || error.message}`);
```

Low risk in an MCP context, but it can surface internal details.

Desired outcome: error messages are useful without leaking sensitive internal detail.

### What is already sound (no action required)

- Input validation via zod is solid; numeric IDs are typed as `z.number()`, limiting
  path injection through endpoints.
- No `eval`, shell execution, dynamic `require`, or disabled TLS verification.
- No hardcoded secrets in the source.

## Requirements

### Requirement 1: Credentials supplied out-of-band

**User story:** As an operator, I want to provide WordPress credentials through
environment variables or a config file, so that my application password never passes
through the LLM context or message logs.

> Authentication method: per official WordPress guidance
> ([Authentication handbook](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/),
> [Application Passwords](https://developer.wordpress.org/advanced-administration/security/application-passwords/)),
> this server uses an **Application Password on a dedicated, least-privilege service
> user** over HTTPS. Cookie auth is browser-only and unusable here; JWT/OAuth are
> non-core plugins that add surface without addressing the actual risks. See the
> "Authentication approach" section in `design.md` for the full rationale and role
> guidance.

#### Acceptance criteria
1. WHEN the server starts THEN it SHALL read `username` and `password` from environment
   variables (or a local config file) rather than tool parameters.
2. WHEN a tool is invoked THEN the tool schema SHALL NOT require `username` or `password`
   as input fields.
3. IF required credentials are missing at startup THEN the server SHALL fail fast with a
   clear error message and not start serving tools.
4. WHEN credentials are loaded THEN they SHALL NOT be written to logs or returned in tool
   responses.

### Requirement 2: HTTPS enforcement

**User story:** As an operator, I want the server to refuse plaintext connections, so
that credentials are never sent in cleartext.

#### Acceptance criteria
1. WHEN a request target uses a scheme other than `https:` THEN the server SHALL reject
   the request before sending any data.
2. IF a local-development override is provided (explicit, opt-in configuration) THEN
   `http:` to loopback addresses MAY be permitted, and this SHALL be off by default.
3. WHEN a request is rejected for using a disallowed scheme THEN the error message SHALL
   explain the HTTPS requirement.

### Requirement 3: SSRF protection

**User story:** As an operator, I want the server to only talk to my intended WordPress
host, so that prompts cannot redirect it to internal or metadata endpoints.

#### Acceptance criteria
1. WHEN the server is configured THEN the target site host SHALL be fixed by
   configuration rather than supplied per tool call.
2. WHEN a resolved request host is a private, loopback, or link-local address THEN the
   request SHALL be blocked unless the local-development override is explicitly enabled.
3. WHEN a response is an HTTP redirect to a different host THEN credentials SHALL NOT be
   forwarded to the redirect target.
4. IF an allowlist is configured THEN only hosts on the allowlist SHALL be contacted.

### Requirement 4: Dependency remediation

**User story:** As an operator, I want the dependency tree free of known high and
critical vulnerabilities, so that I am not exposed to published exploits.

#### Acceptance criteria
1. WHEN `npm audit` runs THEN it SHALL report zero high and zero critical vulnerabilities.
2. WHEN dependencies are updated THEN `axios` and `@modelcontextprotocol/sdk` SHALL be at
   versions that resolve the advisories listed in the analysis.
3. WHEN versions are chosen THEN they SHALL be pinned or constrained to known-good
   releases, and the project SHALL still build (`npm run build`).

### Requirement 5: Documentation accuracy

**User story:** As a user, I want the README to describe the tools that actually exist,
so that I can trust the artifact I am running.

#### Acceptance criteria
1. WHEN the README lists tools THEN every listed tool SHALL exist in `src/index.ts` with
   matching name and parameters.
2. IF a tool exists in code but is undocumented THEN it SHALL be added to the README.
3. WHEN credential handling changes (Requirement 1) THEN the README SHALL document the
   new configuration method.

### Requirement 6: Destructive operation guardrails

**User story:** As an operator, I want destructive tools gated, so that content is not
deleted by accident.

#### Acceptance criteria
1. WHEN a destructive tool (`delete-user`, `delete-post` with force, `delete-category`)
   is invoked THEN it SHALL require an explicit confirmation flag or an environment-level
   opt-in.
2. IF destructive operations are disabled by configuration THEN the corresponding tools
   SHALL refuse with a clear message.

### Requirement 7: Safe error reporting

**User story:** As an operator, I want error messages that help debugging without leaking
internal detail.

#### Acceptance criteria
1. WHEN an upstream error occurs THEN the response SHALL include a useful summary
   (status and a short message) without echoing full upstream payloads.
2. WHEN an error is reported THEN it SHALL NOT include credentials or full request URLs
   containing sensitive query parameters.
