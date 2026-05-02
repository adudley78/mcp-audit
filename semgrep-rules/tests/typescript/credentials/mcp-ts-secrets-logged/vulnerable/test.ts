/**
 * Vulnerable TypeScript secrets-logged examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

const apiKey = process.env.API_KEY ?? "";
const token = process.env.TOKEN ?? "";
const password = process.env.PASSWORD ?? "";
const authToken = process.env.AUTH_TOKEN ?? "";

// ruleid: mcp-ts-console-log-sensitive
console.log(apiKey);

// ruleid: mcp-ts-console-log-sensitive
console.debug(token);

// ruleid: mcp-ts-console-log-sensitive
console.warn(password);

// ruleid: mcp-ts-console-error-sensitive
console.error(authToken);

async function handler(secret: string) {
  // ruleid: mcp-ts-console-log-sensitive
  console.log(secret);

  // ruleid: mcp-ts-console-error-sensitive
  console.error(secret);
}
