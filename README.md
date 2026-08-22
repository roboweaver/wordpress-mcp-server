[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/prathammanocha-wordpress-mcp-server-badge.png)](https://mseep.ai/app/prathammanocha-wordpress-mcp-server)

# Comprehensive WordPress MCP Server

A Model Context Protocol (MCP) server that lets AI assistants interact with a WordPress site through the WordPress REST API. It provides tools for managing users, posts, comments, and categories, plus a set of Jetpack/WP.com site-stats tools.

> **Breaking change:** Tools no longer accept `siteUrl`, `username`, or `password` parameters. Credentials and the site URL are now supplied to the server via environment variables (see [Server configuration](#server-configuration-environment-variables)). Update your MCP client configuration accordingly.

<a href="https://glama.ai/mcp/servers/@prathammanocha/wordpress-mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@prathammanocha/wordpress-mcp-server/badge" alt="WordPress Server MCP server" />
</a>

## Security model

Credentials and the target site URL are **not** part of the tool surface. They are supplied to the server out-of-band via environment variables (or a JSON config file) and are never passed as per-call tool parameters, so they never flow through the model context. In addition, the server:

- Enforces `https:` for all requests (plain `http:` is allowed only to loopback addresses, and only when explicitly enabled for local development).
- Blocks requests to private, loopback, link-local, and unique-local IP ranges (SSRF protection), unless explicitly enabled.
- Supports an optional host allowlist.
- Gates destructive operations (deleting users, force-deleting posts, deleting categories) behind an explicit opt-in.
- Does not follow redirects (`maxRedirects: 0`) so the `Authorization` header cannot leak to another host.
- Returns sanitized errors (HTTP status + a short upstream message only), never URLs with query params, headers, or credentials.

## Prerequisites

- Node.js v20 or higher (the build runs on v18+, but the test toolchain requires v20+)
- A WordPress site with the REST API enabled (default in WordPress 4.7+)
- A WordPress **Application Password** for a dedicated, least-privilege service user

## Installation

1. Clone this repository:
   ```bash
   git clone [repository-url]
   cd wordpress-mcp-server
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
   In CI, prefer `npm ci` for a reproducible install from the lockfile.
3. Build the server:
   ```bash
   npm run build
   ```

## WordPress configuration

1. Ensure the WordPress REST API is enabled (default in WordPress 4.7+).
2. Create an Application Password (WordPress 5.6+):
   - Log in to the WordPress admin panel.
   - Go to **Users → Profile** (or **Users → All Users → Edit** for the service user).
   - Scroll to **Application Passwords**.
   - Enter a name (e.g. "MCP Server") and click **Add New Application Password**.
   - Copy the generated password — it is shown only once.

For least privilege, provision a dedicated service user with the lowest role that covers the tools you actually use. Content-only workflows work at the **Editor** level; the `create-user` / `update-user` / `delete-user` tools and the stats tools require admin-level capabilities. WordPress enforces these capability limits server-side regardless of what the model is prompted to do.

## Server configuration (environment variables)

Configuration is read from environment variables. A JSON file referenced by `WP_MCP_CONFIG` may override individual values.

| Variable                 | Required | Default | Description                                                                                 |
| ------------------------ | -------- | ------- | ------------------------------------------------------------------------------------------- |
| `WP_SITE_URL`            | yes      | —       | Base URL of the WordPress site. Must be `https:` unless an insecure-http override is set.    |
| `WP_USERNAME`            | yes      | —       | Service-user login.                                                                          |
| `WP_APP_PASSWORD`        | yes      | —       | Application Password for the service user.                                                   |
| `WP_ALLOW_INSECURE_HTTP` | no       | `false` | Allow `http:` to loopback hosts only (local development). Non-loopback `http:` is rejected.  |
| `WP_ALLOW_PRIVATE_HOSTS` | no       | `false` | Allow private / loopback / link-local / unique-local IP targets (SSRF protection off).       |
| `WP_ALLOW_DESTRUCTIVE`   | no       | `false` | Allow destructive tools: `delete-user`, `delete-post` (force), `delete-category`.            |
| `WP_ALLOWED_HOSTS`       | no       | —       | Comma-separated host allowlist. When set, only these hosts may be targeted.                  |
| `WP_MCP_CONFIG`          | no       | —       | Path to a JSON config file whose values override the environment.                            |

Boolean toggles are truthy only for the string `true` (case-insensitive); any other value is treated as `false`. The server fails fast on startup (exit 1) if a required variable is missing or invalid; error messages name the missing keys but never their values.

> **Note:** Connecting to a loopback `http:` WordPress instance for local development requires **both** `WP_ALLOW_INSECURE_HTTP=true` and `WP_ALLOW_PRIVATE_HOSTS=true`, since a loopback address is also a private range.

## MCP configuration

Add the server to your MCP settings, supplying credentials via `env`:

```json
{
  "mcpServers": {
    "wordpress": {
      "command": "node",
      "args": ["path/to/wordpress-mcp-server/build/index.js"],
      "env": {
        "WP_SITE_URL": "https://example.com",
        "WP_USERNAME": "your-service-user",
        "WP_APP_PASSWORD": "xxxx xxxx xxxx xxxx xxxx xxxx"
      }
    }
  }
}
```

## Available tools

Tools take only domain parameters (such as `postId`, `perPage`, `userId`). Site URL and credentials come from configuration, not from tool arguments.

### User management
| Tool          | Description                                                        |
| ------------- | ------------------------------------------------------------------ |
| `get-users`   | Get a list of users with advanced filtering options.               |
| `get-user`    | Get a specific user by ID.                                         |
| `create-user` | Create a new WordPress user.                                       |
| `update-user` | Update an existing WordPress user.                                 |
| `delete-user` | Delete a WordPress user. *(requires `WP_ALLOW_DESTRUCTIVE=true`)*   |

### Post management
| Tool          | Description                                                                       |
| ------------- | --------------------------------------------------------------------------------- |
| `list-posts`  | Get a list of posts with comprehensive filtering options.                         |
| `get-post`    | Get a specific post by ID.                                                        |
| `create-post` | Create a new WordPress post.                                                      |
| `update-post` | Update an existing WordPress post.                                                |
| `delete-post` | Delete a post (move to trash). Permanent `force` deletion requires `WP_ALLOW_DESTRUCTIVE=true`. |

### Comment management
| Tool             | Description                              |
| ---------------- | ---------------------------------------- |
| `get-comments`   | Get a list of comments from the site.    |
| `create-comment` | Create a new comment on a post.          |

### Category management
| Tool              | Description                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| `list-categories` | Get a list of categories with filtering options.                         |
| `get-category`    | Get a specific category by ID.                                           |
| `create-category` | Create a new WordPress category.                                         |
| `update-category` | Update an existing WordPress category.                                   |
| `delete-category` | Delete a WordPress category. *(requires `WP_ALLOW_DESTRUCTIVE=true`)*     |

### Site stats (Jetpack / WP.com)
These tools require a Jetpack-connected site and elevated privileges.

| Tool                    | Description                                                       |
| ----------------------- | ---------------------------------------------------------------- |
| `get-stats-highlights`  | Highlight metrics for the last seven days.                       |
| `get-stats-summary`     | Summarized views, visitors, likes, and comments.                 |
| `get-top-posts`         | Top posts and pages by views.                                    |
| `get-referrers`         | Site referrers.                                                  |
| `get-country-views`     | Views by country.                                                |
| `get-post-stats`        | Views for a specific post.                                       |
| `get-site-stats`        | Comprehensive site stats.                                        |
| `report-referrer-spam`  | Report a referrer as spam.                                       |
| `remove-referrer-spam`  | Unreport a referrer as spam.                                     |
| `get-clicks`            | Outbound clicks.                                                 |
| `get-search-terms`      | Search terms used to find the site.                              |
| `get-streak-stats`      | Calendar-heatmap stats showing publishing activity.              |

## Security considerations

- Use HTTPS for your WordPress site (enforced by default).
- Use an Application Password for a dedicated, least-privilege service user — never your main WordPress password.
- Keep `WP_ALLOW_DESTRUCTIVE`, `WP_ALLOW_INSECURE_HTTP`, and `WP_ALLOW_PRIVATE_HOSTS` off unless you specifically need them.
- Use `WP_ALLOWED_HOSTS` to pin the server to known hosts.
- Rotate Application Passwords periodically and revoke unused ones.

## Development

```bash
npm run build   # compile TypeScript to build/
npm test        # run the vitest unit tests
npm run dev     # watch mode (recompile on change)
```

Unit tests cover the security-critical units: target validation / SSRF guard (`validateTarget`) and configuration loading (`loadConfig`).

## License

This project is licensed under the ISC License.

## Contributing

Contributions are welcome. Please fork the repository, create a feature branch, run `npm run build` and `npm test`, and submit a pull request.
