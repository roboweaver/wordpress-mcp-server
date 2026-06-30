import { describe, it, expect, afterEach } from "vitest";
import { writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./config.js";

const validEnv = {
  WP_SITE_URL: "https://example.com",
  WP_USERNAME: "svc",
  WP_APP_PASSWORD: "app-pass",
};

const tempPaths: string[] = [];
function writeTempJson(obj: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "wp-mcp-test-"));
  const file = join(dir, "config.json");
  writeFileSync(file, JSON.stringify(obj), "utf-8");
  tempPaths.push(dir);
  return file;
}

afterEach(() => {
  for (const p of tempPaths.splice(0)) {
    rmSync(p, { recursive: true, force: true });
  }
});

describe("loadConfig - required keys", () => {
  it("throws when all required keys are missing, naming each key", () => {
    let message = "";
    try {
      loadConfig({});
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/WP_SITE_URL/);
    expect(message).toMatch(/WP_USERNAME/);
    expect(message).toMatch(/WP_APP_PASSWORD/);
  });

  it("throws when only WP_APP_PASSWORD is missing", () => {
    expect(() =>
      loadConfig({ WP_SITE_URL: "https://example.com", WP_USERNAME: "svc" })
    ).toThrow(/WP_APP_PASSWORD/);
  });

  it("rejects a WP_SITE_URL that is not a valid URL", () => {
    expect(() => loadConfig({ ...validEnv, WP_SITE_URL: "not-a-url" })).toThrow(/valid URL/);
  });

  it("does not leak secret values in the error message", () => {
    let message = "";
    try {
      // missing site url, but password present – ensure the secret is not echoed
      loadConfig({ WP_USERNAME: "svc", WP_APP_PASSWORD: "super-secret-value" });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).not.toMatch(/super-secret-value/);
  });

  it("returns a valid config with secure defaults for the toggles", () => {
    const cfg = loadConfig({ ...validEnv });
    expect(cfg.siteUrl).toBe("https://example.com");
    expect(cfg.username).toBe("svc");
    expect(cfg.password).toBe("app-pass");
    expect(cfg.allowInsecureHttp).toBe(false);
    expect(cfg.allowPrivateHosts).toBe(false);
    expect(cfg.allowDestructive).toBe(false);
    expect(cfg.allowedHosts).toBeUndefined();
  });

  it("strips trailing slashes from WP_SITE_URL", () => {
    expect(loadConfig({ ...validEnv, WP_SITE_URL: "https://example.com/" }).siteUrl).toBe(
      "https://example.com"
    );
    expect(loadConfig({ ...validEnv, WP_SITE_URL: "https://example.com///" }).siteUrl).toBe(
      "https://example.com"
    );
  });
});

describe("loadConfig - boolean toggle parsing", () => {
  it('treats "true" (any case) as true and everything else as false', () => {
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "true" }).allowInsecureHttp).toBe(true);
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "TRUE" }).allowInsecureHttp).toBe(true);
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "True" }).allowInsecureHttp).toBe(true);
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "false" }).allowInsecureHttp).toBe(false);
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "1" }).allowInsecureHttp).toBe(false);
    expect(loadConfig({ ...validEnv, WP_ALLOW_INSECURE_HTTP: "yes" }).allowInsecureHttp).toBe(false);
  });

  it("parses WP_ALLOW_DESTRUCTIVE independently (destructive gating input)", () => {
    expect(loadConfig({ ...validEnv }).allowDestructive).toBe(false);
    expect(loadConfig({ ...validEnv, WP_ALLOW_DESTRUCTIVE: "true" }).allowDestructive).toBe(true);
  });

  it("parses WP_ALLOW_PRIVATE_HOSTS", () => {
    expect(loadConfig({ ...validEnv, WP_ALLOW_PRIVATE_HOSTS: "true" }).allowPrivateHosts).toBe(true);
  });
});

describe("loadConfig - allowedHosts list parsing", () => {
  it("splits a comma-separated list and trims whitespace", () => {
    const cfg = loadConfig({ ...validEnv, WP_ALLOWED_HOSTS: " a.com , b.com ,c.com " });
    expect(cfg.allowedHosts).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("treats an empty WP_ALLOWED_HOSTS as undefined (no restriction)", () => {
    expect(loadConfig({ ...validEnv, WP_ALLOWED_HOSTS: "" }).allowedHosts).toBeUndefined();
    expect(loadConfig({ ...validEnv, WP_ALLOWED_HOSTS: "   " }).allowedHosts).toBeUndefined();
  });
});

describe("loadConfig - WP_MCP_CONFIG file override", () => {
  it("lets a JSON config file override environment values", () => {
    const file = writeTempJson({ siteUrl: "https://from-file.example.com", allowDestructive: true });
    const cfg = loadConfig({ ...validEnv, WP_MCP_CONFIG: file });
    expect(cfg.siteUrl).toBe("https://from-file.example.com");
    expect(cfg.allowDestructive).toBe(true);
    // values not in the file fall back to env
    expect(cfg.username).toBe("svc");
  });

  it("supports allowedHosts as an array in the config file", () => {
    const file = writeTempJson({ allowedHosts: ["x.com", "y.com"] });
    const cfg = loadConfig({ ...validEnv, WP_MCP_CONFIG: file });
    expect(cfg.allowedHosts).toEqual(["x.com", "y.com"]);
  });

  it("throws a descriptive error when the config file is missing", () => {
    expect(() =>
      loadConfig({ ...validEnv, WP_MCP_CONFIG: "/nonexistent/path/to/config.json" })
    ).toThrow(/not found/);
  });
});
