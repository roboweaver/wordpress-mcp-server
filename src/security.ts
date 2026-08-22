import ipaddr from 'ipaddr.js';
import type { WPConfig } from './config.js';

/**
 * Resolves a hostname to a list of IP address strings.
 * Injectable so tests can run without real DNS.
 */
export type HostResolver = (hostname: string) => Promise<string[]>;

/** Default resolver backed by the OS resolver (node:dns). */
const defaultResolver: HostResolver = async (hostname) => {
  const { lookup } = await import('node:dns/promises');
  const results = await lookup(hostname, { all: true });
  return results.map((r) => r.address);
};

/**
 * Normalize a URL hostname for comparison and classification:
 * strip IPv6 brackets, lowercase, and drop a single trailing dot (FQDN form).
 */
function normalizeHostname(hostname: string): string {
  let h = hostname.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) {
    h = h.slice(1, -1);
  }
  if (h.endsWith('.')) {
    h = h.slice(0, -1);
  }
  return h;
}

/**
 * Classify an IP string into an address range using ipaddr.js.
 * IPv4-mapped IPv6 addresses are unwrapped to their embedded IPv4 first so the
 * underlying range is evaluated. Returns null when the input is not a valid IP
 * (i.e. it is a DNS name).
 */
function classifyRange(ipStr: string): string | null {
  if (!ipaddr.isValid(ipStr)) return null;
  let addr = ipaddr.parse(ipStr);
  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      addr = v6.toIPv4Address();
    }
  }
  return addr.range();
}

/**
 * Determines if a hostname or IP string represents a private/reserved address.
 * Treats `localhost` and any non-global-unicast IP (loopback, private,
 * link-local, unique-local, reserved, multicast, ...) as private. DNS names
 * (non-IP strings) return false here and are handled via resolution.
 */
function isPrivateAddress(host: string): boolean {
  const h = normalizeHostname(host);
  if (h === 'localhost') return true;
  const range = classifyRange(h);
  if (range === null) return false;
  return range !== 'unicast';
}

/** Returns true if the (normalized) hostname is an IP literal (v4 or v6). */
function isIpLiteral(hostname: string): boolean {
  return ipaddr.isValid(normalizeHostname(hostname));
}

/**
 * Returns true if the hostname is a loopback address literal or `localhost`.
 */
function isLoopback(hostname: string): boolean {
  const h = normalizeHostname(hostname);
  if (h === 'localhost') return true;
  return classifyRange(h) === 'loopback';
}

/**
 * Validates a target URL against the security policy defined by config.
 *
 * Checks performed:
 * 1. URL must be parseable.
 * 2. Scheme must be `https:` unless `allowInsecureHttp` is true AND host is loopback.
 * 3. Host must not be a private/reserved address unless `allowPrivateHosts` is true.
 *    For DNS names, the host is resolved and every resolved IP is checked
 *    (DNS-rebinding / indirect-SSRF mitigation).
 * 4. Host must be in `allowedHosts` (normalized comparison) if that list is configured.
 *
 * Rejects (throws) with a descriptive message on validation failure.
 */
export async function validateTarget(
  url: string,
  config: WPConfig,
  resolver: HostResolver = defaultResolver
): Promise<void> {
  // 1. Parse URL
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: the target URL could not be parsed.`);
  }

  const { protocol } = parsed;
  const host = normalizeHostname(parsed.hostname);

  // 2. Scheme check
  if (protocol !== 'https:') {
    if (protocol === 'http:') {
      if (!config.allowInsecureHttp) {
        throw new Error(
          `HTTPS is required. The request was rejected because the target uses http:. ` +
            `Set WP_ALLOW_INSECURE_HTTP=true to permit http: to loopback addresses for local development.`
        );
      }
      if (!isLoopback(host)) {
        throw new Error(
          `HTTP is only allowed for loopback addresses (localhost, 127.x.x.x, ::1) when ` +
            `WP_ALLOW_INSECURE_HTTP is enabled. The host "${host}" is not a loopback address.`
        );
      }
    } else {
      throw new Error(
        `Unsupported protocol "${protocol}". Only https: (and http: for loopback in dev mode) are allowed.`
      );
    }
  }

  // 3. Private/reserved host check
  if (!config.allowPrivateHosts) {
    if (isIpLiteral(host)) {
      if (isPrivateAddress(host)) {
        throw new Error(
          `Request blocked: the host "${host}" is a private or reserved address. ` +
            `Set WP_ALLOW_PRIVATE_HOSTS=true to connect to a local or private-network WordPress instance.`
        );
      }
    } else if (host === 'localhost') {
      throw new Error(
        `Request blocked: the host "${host}" is a private or reserved address. ` +
          `Set WP_ALLOW_PRIVATE_HOSTS=true to connect to a local or private-network WordPress instance.`
      );
    } else {
      // DNS name: resolve and check every resolved address to mitigate
      // DNS-rebinding and indirect DNS-based SSRF.
      let addresses: string[];
      try {
        addresses = await resolver(host);
      } catch {
        throw new Error(`Request blocked: the host "${host}" could not be resolved.`);
      }
      const blocked = addresses.find((ip) => isPrivateAddress(ip));
      if (blocked) {
        throw new Error(
          `Request blocked: the host "${host}" resolves to a private or reserved address (${blocked}). ` +
            `Set WP_ALLOW_PRIVATE_HOSTS=true to connect to a local or private-network WordPress instance.`
        );
      }
    }
  }

  // 4. Allowlist enforcement (normalized comparison)
  if (config.allowedHosts && config.allowedHosts.length > 0) {
    const allowed = config.allowedHosts.map((h) => normalizeHostname(h));
    if (!allowed.includes(host)) {
      throw new Error(
        `Request blocked: the host "${host}" is not in the configured allowed hosts list ` +
          `(${allowed.join(', ')}).`
      );
    }
  }
}
