/**
 * Vulnerable TypeScript credentials examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

// ruleid: mcp-ts-hardcoded-api-key
const api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890-hardcoded";

// ruleid: mcp-ts-hardcoded-api-key
const secret = "my-very-long-hardcoded-secret-value-for-mcp-server";

// ruleid: mcp-ts-hardcoded-api-key-let
let password = "hardcoded_password_value_that_is_way_too_long_here";

// ruleid: mcp-ts-hardcoded-api-key
const auth_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example";
