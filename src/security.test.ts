import { describe, it, expect } from "vitest";
import { validateTarget, type HostResolver } from "./security.js";
import type { WPConfig } from "./config.js";

/** Build a WPConfig with sensible secure defaults, overridable per test. */
function makeConfig(overrides: Partial<WPConfig> = {}): WPConfig {
  return {
    siteUrl: "https://example.com",
    username: "svc",
    password: "pw",
    allowInsecureHttp: false,
    allowPrivateHosts: false,
    allowDestructive: false,
    ...overrides,
  };
}

/** Resolver stub that returns fixed public addresses (no real DNS). */
const publicResolver: HostResolver = async () => ["93.184.216.34"];
/** Resolver stub that returns a private address. */
const privateResolver: HostResolver = async () => ["10.0.0.5"];
/** Resolver that always fails. */
const failingResolver: HostResolver = async () => {
  throw new Error("ENOTFOUND");
};
/** Resolver that must never be called (IP literals should skip DNS). */
const neverResolver: HostResolver = async () => {
  throw new Error("resolver should not be called for IP literals");
};

describe("validateTarget - scheme enforcement", () => {
  it("allows https to a public host by default", async () => {
    await expect(
      validateTarget("https://example.com/wp-json/wp/v2/posts", makeConfig(), publicResolver)
    ).resolves.toBeUndefined();
  });

  it("rejects http when allowInsecureHttp is false", async () => {
    await expect(validateTarget("http://example.com", makeConfig(), publicResolver)).rejects.toThrow(
      /HTTPS is required/
    );
  });

  it("rejects http to a non-loopback host even when allowInsecureHttp is true", async () => {
    await expect(
      validateTarget("http://example.com", makeConfig({ allowInsecureHttp: true }), publicResolver)
    ).rejects.toThrow(/only allowed for loopback/);
  });

  it("allows http to loopback when both insecure-http and private-hosts are enabled", async () => {
    await expect(
      validateTarget(
        "http://127.0.0.1:8080",
        makeConfig({ allowInsecureHttp: true, allowPrivateHosts: true }),
        neverResolver
      )
    ).resolves.toBeUndefined();
  });

  it("still blocks http loopback when private hosts are not allowed", async () => {
    await expect(
      validateTarget("http://127.0.0.1", makeConfig({ allowInsecureHttp: true }), neverResolver)
    ).rejects.toThrow(/private or reserved/);
  });

  it("rejects unsupported schemes like ftp", async () => {
    await expect(validateTarget("ftp://example.com", makeConfig(), publicResolver)).rejects.toThrow(
      /Unsupported protocol/
    );
  });

  it("rejects unparseable URLs", async () => {
    await expect(validateTarget("not a url", makeConfig(), publicResolver)).rejects.toThrow(
      /could not be parsed/
    );
  });
});

describe("validateTarget - private / reserved IP literals", () => {
  const blocked = [
    "https://169.254.169.254", // link-local (cloud metadata)
    "https://10.0.0.5", // 10/8
    "https://172.16.0.1", // 172.16/12
    "https://172.31.255.255", // 172.16/12 upper bound
    "https://192.168.1.1", // 192.168/16
    "https://127.0.0.1", // loopback
    "https://[::1]", // IPv6 loopback
    "https://[fc00::1]", // unique-local
    "https://[fd12:3456::1]", // unique-local
    "https://[fe80::1]", // link-local
    "https://[::ffff:10.0.0.1]", // IPv4-mapped IPv6 -> private
  ];

  for (const url of blocked) {
    it(`blocks ${url} unless allowPrivateHosts (no DNS used)`, async () => {
      await expect(validateTarget(url, makeConfig(), neverResolver)).rejects.toThrow(
        /private or reserved/
      );
    });
  }

  it("blocks localhost (name) without DNS", async () => {
    await expect(validateTarget("https://localhost", makeConfig(), neverResolver)).rejects.toThrow(
      /private or reserved/
    );
  });

  it("allows a private IP literal when allowPrivateHosts is true", async () => {
    await expect(
      validateTarget("https://10.0.0.5", makeConfig({ allowPrivateHosts: true }), neverResolver)
    ).resolves.toBeUndefined();
  });

  it("does not misclassify a public IP as private", async () => {
    await expect(
      validateTarget("https://8.8.8.8", makeConfig(), neverResolver)
    ).resolves.toBeUndefined();
  });

  it("does not misclassify 172.15.x or 172.32.x as private (outside 172.16/12)", async () => {
    await expect(
      validateTarget("https://172.15.0.1", makeConfig(), neverResolver)
    ).resolves.toBeUndefined();
    await expect(
      validateTarget("https://172.32.0.1", makeConfig(), neverResolver)
    ).resolves.toBeUndefined();
  });
});

describe("validateTarget - DNS-based SSRF mitigation", () => {
  it("blocks a DNS name that resolves to a private address", async () => {
    await expect(
      validateTarget("https://rebind.example.com", makeConfig(), privateResolver)
    ).rejects.toThrow(/resolves to a private or reserved address/);
  });

  it("allows a DNS name that resolves to public addresses", async () => {
    await expect(
      validateTarget("https://good.example.com", makeConfig(), publicResolver)
    ).resolves.toBeUndefined();
  });

  it("blocks when the host cannot be resolved", async () => {
    await expect(
      validateTarget("https://nope.example.com", makeConfig(), failingResolver)
    ).rejects.toThrow(/could not be resolved/);
  });

  it("skips DNS resolution entirely when allowPrivateHosts is true", async () => {
    await expect(
      validateTarget("https://anything.example.com", makeConfig({ allowPrivateHosts: true }), neverResolver)
    ).resolves.toBeUndefined();
  });
});

describe("validateTarget - allowlist enforcement", () => {
  it("permits a host that is in allowedHosts", async () => {
    await expect(
      validateTarget(
        "https://allowed.example.com",
        makeConfig({ allowedHosts: ["allowed.example.com"] }),
        publicResolver
      )
    ).resolves.toBeUndefined();
  });

  it("blocks a host that is not in allowedHosts", async () => {
    await expect(
      validateTarget(
        "https://other.example.com",
        makeConfig({ allowedHosts: ["allowed.example.com"] }),
        publicResolver
      )
    ).rejects.toThrow(/not in the configured allowed hosts/);
  });

  it("normalizes case and trailing dot when matching the allowlist", async () => {
    // allowlist entry has mixed case; URL host has a trailing dot (FQDN form)
    await expect(
      validateTarget(
        "https://allowed.example.com./wp-json",
        makeConfig({ allowedHosts: ["Allowed.Example.COM"] }),
        publicResolver
      )
    ).resolves.toBeUndefined();
  });

  it("ignores an empty allowlist (no restriction)", async () => {
    await expect(
      validateTarget("https://anything.example.com", makeConfig({ allowedHosts: [] }), publicResolver)
    ).resolves.toBeUndefined();
  });
});
