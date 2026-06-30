import { isIPv4, isIPv6 } from 'node:net';
import type { WPConfig } from './config.js';

/**
 * Returns true if the given hostname string is a loopback address.
 * Covers `localhost`, `127.x.x.x`, and `::1`.
 */
function isLoopback(hostname: string): boolean {
  if (hostname === 'localhost') return true;
  if (hostname === '::1' || hostname === '[::1]') return true;
  if (isIPv4(hostname)) {
    return hostname.startsWith('127.');
  }
  // Bracket-stripped IPv6 check
  const bare = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
  if (bare === '::1') return true;
  return false;
}

/**
 * Returns true if the given IPv4 address string falls in a private/reserved range:
 * - 10.0.0.0/8
 * - 172.16.0.0/12
 * - 192.168.0.0/16
 * - 127.0.0.0/8 (loopback)
 * - 169.254.0.0/16 (link-local)
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return false;

  const [a, b] = parts;

  // 127.0.0.0/8 – loopback
  if (a === 127) return true;
  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 – link-local
  if (a === 169 && b === 254) return true;

  return false;
}

/**
 * Returns true if the given IPv6 address string (without brackets) falls in a
 * private/reserved range:
 * - ::1 (loopback)
 * - fc00::/7 (unique-local, covers fc00:: and fd00::)
 * - fe80::/10 (link-local)
 */
function isPrivateIPv6(ip: string): boolean {
  // Normalize: strip brackets if present
  const bare = ip.startsWith('[') && ip.endsWith(']') ? ip.slice(1, -1) : ip;

  if (bare === '::1') return true;

  // Expand enough to check the first hextet
  const lower = bare.toLowerCase();
  // fc00::/7 covers fc00:: through fdff::
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  // fe80::/10 covers fe80:: through febf::
  if (lower.startsWith('fe8') || lower.startsWith('fe9') ||
      lower.startsWith('fea') || lower.startsWith('feb')) return true;

  return false;
}

/**
 * Determines if a hostname is a private/reserved IP address.
 * Returns true for private IPv4 ranges, private IPv6 ranges, and `localhost`.
 */
function isPrivateHost(hostname: string): boolean {
  if (hostname === 'localhost') return true;

  // Direct IPv4 check
  if (isIPv4(hostname)) {
    return isPrivateIPv4(hostname);
  }

  // IPv6 literal (may be bracketed in URL host)
  const bare = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  if (isIPv6(bare)) {
    return isPrivateIPv6(bare);
  }

  return false;
}

/**
 * Validates a target URL against the security policy defined by config.
 *
 * Checks performed:
 * 1. URL must be parseable.
 * 2. Scheme must be `https:` unless `allowInsecureHttp` is true AND host is loopback.
 * 3. Host must not be a private/reserved IP unless `allowPrivateHosts` is true.
 * 4. Host must be in `allowedHosts` if that list is configured.
 *
 * Throws an Error with a descriptive message on validation failure.
 */
export function validateTarget(url: string, config: WPConfig): void {
  // 1. Parse URL
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(
      `Invalid URL: the target URL could not be parsed.`
    );
  }

  const { protocol, hostname } = parsed;

  // 2. Scheme check
  if (protocol !== 'https:') {
    if (protocol === 'http:') {
      if (!config.allowInsecureHttp) {
        throw new Error(
          `HTTPS is required. The request was rejected because the target uses http:. ` +
          `Set WP_ALLOW_INSECURE_HTTP=true to permit http: to loopback addresses for local development.`
        );
      }
      // allowInsecureHttp is true – only permit loopback
      if (!isLoopback(hostname)) {
        throw new Error(
          `HTTP is only allowed for loopback addresses (localhost, 127.x.x.x, ::1) when ` +
          `WP_ALLOW_INSECURE_HTTP is enabled. The host "${hostname}" is not a loopback address.`
        );
      }
    } else {
      throw new Error(
        `Unsupported protocol "${protocol}". Only https: (and http: for loopback in dev mode) are allowed.`
      );
    }
  }

  // 3. Private/reserved host check
  if (!config.allowPrivateHosts && isPrivateHost(hostname)) {
    throw new Error(
      `Request blocked: the host "${hostname}" resolves to a private or reserved address range. ` +
      `Set WP_ALLOW_PRIVATE_HOSTS=true if you intend to connect to a local or private-network WordPress instance.`
    );
  }

  // 4. Allowlist enforcement
  if (config.allowedHosts && config.allowedHosts.length > 0) {
    if (!config.allowedHosts.includes(hostname)) {
      throw new Error(
        `Request blocked: the host "${hostname}" is not in the configured allowed hosts list ` +
        `(${config.allowedHosts.join(', ')}).`
      );
    }
  }
}
