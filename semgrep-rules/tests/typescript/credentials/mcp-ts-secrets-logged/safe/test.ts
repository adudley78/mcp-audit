/**
 * Safe TypeScript secrets-logged examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-console-log-sensitive
 * and mcp-ts-console-error-sensitive.
 */

// ok: mcp-ts-console-log-sensitive — non-credential variable name
const userId = "user_123";
console.log(userId);

// ok: mcp-ts-console-log-sensitive — non-credential variable name
const requestId = "req-abc";
console.debug(requestId);

// ok: mcp-ts-console-log-sensitive — string literal, not a variable
console.log("Server started on port 3000");

// ok: mcp-ts-console-error-sensitive — string literal
console.error("Connection failed");

// ok: mcp-ts-console-log-sensitive — non-credential name (status message)
const statusMessage = "OK";
console.warn(statusMessage);

async function handler(result: string, errorMessage: string) {
  // ok: mcp-ts-console-log-sensitive — non-credential variable name
  console.log(result);

  // ok: mcp-ts-console-error-sensitive — non-credential variable name
  console.error(errorMessage);
}
