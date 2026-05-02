/**
 * Vulnerable TypeScript missing-input-validation examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

declare function db_query(sql: string): unknown;
declare function exec(cmd: string): unknown;
declare function readFile(path: string): unknown;

// ruleid: mcp-ts-no-type-check-before-use
async function handleSearch(args: Record<string, unknown>) {
  const result = db_query(args["query"]);
  return result;
}

// ruleid: mcp-ts-no-type-check-before-use
async function handleExec(args: Record<string, unknown>) {
  return exec(args["command"]);
}

// ruleid: mcp-ts-no-type-check-before-use
async function handleRead(params: Record<string, unknown>) {
  return readFile(params["path"]);
}
