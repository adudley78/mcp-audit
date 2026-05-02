/**
 * Safe TypeScript credential-in-args examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-credential-default-param.
 */

// ok: mcp-ts-credential-default-param — uses process.env, not a hardcoded literal
function handleRequest(query: string, apiKey: string = process.env.API_KEY ?? "") {
  return fetch(`https://api.example.com?q=${query}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}

// ok: mcp-ts-credential-default-param — empty string default is not a hardcoded credential
async function processData(input: string, password = "") {
  return input;
}

// ok: mcp-ts-credential-default-param — non-credential parameter name
const toolHandler = (args: unknown, timeout = "30000") => {
  return { args, timeout };
};

// ok: mcp-ts-credential-default-param — uses environment variable
const asyncHandler = async (
  request: unknown,
  secret = process.env.SECRET ?? "",
) => {
  return request;
};
