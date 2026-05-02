/**
 * Safe TypeScript description-obfuscated-content examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-description-base64-content
 * and mcp-ts-description-unicode-escape.
 */

// ok: mcp-ts-description-base64-content — plain human-readable description
const description = "Searches the filesystem for files matching a given pattern";

// ok: mcp-ts-description-base64-content — short string, not base64 length
let toolDescription = "Read file";

// ok: mcp-ts-description-base64-content — no base64 content in description
const tool = {
  name: "search",
  description: "Executes a database query and returns matching rows",
};

// ok: mcp-ts-description-unicode-escape — no unicode escapes in description
const desc = "Processes user input and returns a sanitised result";

// ok: mcp-ts-description-base64-content — variable name does not match description regex
// base64-like content but in a non-description variable
const encodedPayload = "SGVsbG8gV29ybGQgdGhpcyBpcyBiYXNlNjQ=";
