import { z } from "zod";
import { readFileSync } from "node:fs";

/**
 * Configuration for the WordPress MCP server.
 * Credentials and site URL are supplied out-of-band (env vars or config file)
 * and never exposed to the LLM tool surface.
 */
export interface WPConfig {
  siteUrl: string;
  username: string;
  password: string;
  allowInsecureHttp: boolean;
  allowPrivateHosts: boolean;
  allowDestructive: boolean;
  allowedHosts?: string[];
}

/**
 * Zod schema for validating raw configuration input.
 * Boolean toggles accept the string "true" (case-insensitive) as truthy; everything else is false.
 */
const configSchema = z.object({
  siteUrl: z
    .string({ error: "WP_SITE_URL is required" })
    .min(1, "WP_SITE_URL must not be empty")
    .url("WP_SITE_URL must be a valid URL"),
  username: z
    .string({ error: "WP_USERNAME is required" })
    .min(1, "WP_USERNAME must not be empty"),
  password: z
    .string({ error: "WP_APP_PASSWORD is required" })
    .min(1, "WP_APP_PASSWORD must not be empty"),
  allowInsecureHttp: z.boolean().default(false),
  allowPrivateHosts: z.boolean().default(false),
  allowDestructive: z.boolean().default(false),
  allowedHosts: z.array(z.string()).optional(),
});

/**
 * Parse a string value as a boolean toggle.
 * Only the literal string "true" (case-insensitive) is truthy.
 */
function parseBool(value: string | undefined): boolean {
  return value?.toLowerCase() === "true";
}

/**
 * Parse a comma-separated string into a trimmed string array.
 * Returns undefined if the input is empty or undefined.
 */
function parseCommaSeparated(value: string | undefined): string[] | undefined {
  if (!value || value.trim() === "") return undefined;
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Load configuration from an optional JSON config file.
 * Returns a partial raw config object (env-style keys mapped to config keys).
 */
function loadConfigFile(filePath: string): Record<string, unknown> {
  try {
    const content = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(content);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("WP_MCP_CONFIG file must contain a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err: unknown) {
    if (err instanceof SyntaxError) {
      throw new Error(`WP_MCP_CONFIG file contains invalid JSON: ${err.message}`);
    }
    if (err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`WP_MCP_CONFIG file not found: ${filePath}`);
    }
    throw err;
  }
}

/**
 * Load and validate the WordPress MCP server configuration.
 *
 * Sources (later overrides earlier):
 * 1. Environment variables
 * 2. Optional JSON config file (path from WP_MCP_CONFIG env var)
 *
 * Throws a descriptive error naming missing/invalid keys (never values).
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): WPConfig {
  // Start with environment variables
  let siteUrl: string | undefined = env.WP_SITE_URL;
  let username: string | undefined = env.WP_USERNAME;
  let password: string | undefined = env.WP_APP_PASSWORD;
  let allowInsecureHttp = parseBool(env.WP_ALLOW_INSECURE_HTTP);
  let allowPrivateHosts = parseBool(env.WP_ALLOW_PRIVATE_HOSTS);
  let allowDestructive = parseBool(env.WP_ALLOW_DESTRUCTIVE);
  let allowedHosts = parseCommaSeparated(env.WP_ALLOWED_HOSTS);

  // Override with config file if specified
  const configFilePath = env.WP_MCP_CONFIG;
  if (configFilePath) {
    const fileConfig = loadConfigFile(configFilePath);

    if (fileConfig.siteUrl !== undefined) siteUrl = String(fileConfig.siteUrl);
    if (fileConfig.username !== undefined) username = String(fileConfig.username);
    if (fileConfig.password !== undefined) password = String(fileConfig.password);
    if (fileConfig.allowInsecureHttp !== undefined) {
      allowInsecureHttp =
        fileConfig.allowInsecureHttp === true || String(fileConfig.allowInsecureHttp).toLowerCase() === "true";
    }
    if (fileConfig.allowPrivateHosts !== undefined) {
      allowPrivateHosts =
        fileConfig.allowPrivateHosts === true || String(fileConfig.allowPrivateHosts).toLowerCase() === "true";
    }
    if (fileConfig.allowDestructive !== undefined) {
      allowDestructive =
        fileConfig.allowDestructive === true || String(fileConfig.allowDestructive).toLowerCase() === "true";
    }
    if (fileConfig.allowedHosts !== undefined) {
      if (Array.isArray(fileConfig.allowedHosts)) {
        allowedHosts = fileConfig.allowedHosts.map(String).filter((s) => s.length > 0);
      } else if (typeof fileConfig.allowedHosts === "string") {
        allowedHosts = parseCommaSeparated(fileConfig.allowedHosts);
      }
    }
  }

  // Validate the assembled configuration
  const result = configSchema.safeParse({
    siteUrl,
    username,
    password,
    allowInsecureHttp,
    allowPrivateHosts,
    allowDestructive,
    allowedHosts,
  });

  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const path = issue.path.join(".");
      return `  - ${path}: ${issue.message}`;
    });
    throw new Error(
      `Configuration validation failed:\n${issues.join("\n")}\n\nRequired environment variables: WP_SITE_URL, WP_USERNAME, WP_APP_PASSWORD`
    );
  }

  // Normalize the site URL so endpoint concatenation never yields double slashes.
  result.data.siteUrl = result.data.siteUrl.replace(/\/+$/, "");

  return result.data;
}
