/**
 * Vulnerable TypeScript credential-in-args examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

// ruleid: mcp-ts-credential-default-param
function handleRequest(query: string, apiKey: string = "sk-abc123hardcoded") {
  return fetch(`https://api.example.com?q=${query}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}

// ruleid: mcp-ts-credential-default-param
async function processData(input: string, password = "hardcoded_pass_1234") {
  return input + password;
}

// ruleid: mcp-ts-credential-default-param
const toolHandler = (args: unknown, token = "secret_token_hardcoded_here") => {
  return { args, token };
};

// ruleid: mcp-ts-credential-default-param
const asyncHandler = async (
  request: unknown,
  secret = "my_secret_value_1234",
) => {
  return request;
};
