import { describe, it, expect } from "vitest";
import { validateTarget } from "./security.js";
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

describe("validateTarget - scheme enforcement", () => {
  it("allows https to a public host by default", () => {
    expect(() => validateTarget("https://example.com/wp-json/wp/v2/posts", makeConfig())).not.toThrow();
  });

  it("rejects http when allowInsecureHttp is false", () => {
    expect(() => validateTarget("http://example.com", makeConfig())).toThrow(/HTTPS is required/);
  });

  it("rejects http to a non-loopback host even when allowInsecureHttp is true", () => {
    expect(() =>
      validateTarget("http://example.com", makeConfig({ allowInsecureHttp: true }))
    ).toThrow(/only allowed for loopback/);
  });

  it("allows http to loopback when both insecure-http and private-hosts are enabled", () => {
    // 127.0.0.1 passes the scheme (loopback) check but is also a private IP,
    // so allowPrivateHosts must also be true.
    expect(() =>
      validateTarget(
        "http://127.0.0.1:8080",
        makeConfig({ allowInsecureHttp: true, allowPrivateHosts: true })
      )
    ).not.toThrow();
  });

  it("still blocks http loopback when private hosts are not allowed", () => {
    expect(() =>
      validateTarget("http://127.0.0.1", makeConfig({ allowInsecureHttp: true }))
    ).toThrow(/private or reserved/);
  });

  it("rejects unsupported schemes like ftp", () => {
    expect(() => validateTarget("ftp://example.com", makeConfig())).toThrow(/Unsupported protocol/);
  });

  it("rejects unparseable URLs", () => {
    expect(() => validateTarget("not a url", makeConfig())).toThrow(/could not be parsed/);
  });
});

describe("validateTarget - private / reserved range blocking", () => {
  const blocked = [
    "https://169.254.169.254", // link-local (cloud metadata)
    "https://10.0.0.5", // 10/8
    "https://172.16.0.1", // 172.16/12
    "https://172.31.255.255", // 172.16/12 upper bound
    "https://192.168.1.1", // 192.168/16
    "https://127.0.0.1", // loopback
    "https://localhost", // loopback name
    "https://[::1]", // IPv6 loopback
    "https://[fc00::1]", // unique-local
    "https://[fd12:3456::1]", // unique-local
    "https://[fe80::1]", // link-local
  ];

  for (const url of blocked) {
    it(`blocks ${url} unless allowPrivateHosts`, () => {
      expect(() => validateTarget(url, makeConfig())).toThrow(/private or reserved/);
    });
  }

  it("allows a private host when allowPrivateHosts is true", () => {
    expect(() => validateTarget("https://10.0.0.5", makeConfig({ allowPrivateHosts: true }))).not.toThrow();
  });

  it("does not misclassify a public host as private", () => {
    expect(() => validateTarget("https://203.0.113.10", makeConfig())).not.toThrow();
  });

  it("does not misclassify 172.15.x or 172.32.x as private (outside 172.16/12)", () => {
    expect(() => validateTarget("https://172.15.0.1", makeConfig())).not.toThrow();
    expect(() => validateTarget("https://172.32.0.1", makeConfig())).not.toThrow();
  });
});

describe("validateTarget - allowlist enforcement", () => {
  it("permits a host that is in allowedHosts", () => {
    expect(() =>
      validateTarget("https://allowed.example.com", makeConfig({ allowedHosts: ["allowed.example.com"] }))
    ).not.toThrow();
  });

  it("blocks a host that is not in allowedHosts", () => {
    expect(() =>
      validateTarget("https://other.example.com", makeConfig({ allowedHosts: ["allowed.example.com"] }))
    ).toThrow(/not in the configured allowed hosts/);
  });

  it("ignores an empty allowlist (no restriction)", () => {
    expect(() =>
      validateTarget("https://anything.example.com", makeConfig({ allowedHosts: [] }))
    ).not.toThrow();
  });
});
