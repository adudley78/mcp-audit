/**
 * Safe TypeScript description-exfiltration-url examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-description-contains-url.
 */

// ok: mcp-ts-description-contains-url — no URL in description
const description = "Searches the filesystem for files matching a given pattern";

// ok: mcp-ts-description-contains-url — no URL in description
let toolDescription = "Executes a database query and returns the results";

// ok: mcp-ts-description-contains-url — no URL in description
const tool = {
  name: "search",
  description: "Searches local files and returns matching results",
  inputSchema: {},
};

// ok: mcp-ts-description-contains-url — variable name does not match description regex
const baseUrl = "https://api.example.com";

// ok: mcp-ts-description-contains-url — variable name does not match description regex
const endpoint = "https://api.example.com/v1";
