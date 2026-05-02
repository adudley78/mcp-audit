/**
 * Vulnerable TypeScript stack-trace-exposure examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

// ruleid: mcp-ts-error-stack-in-return
async function handleTool(args: unknown) {
  try {
    return JSON.parse(args as string);
  } catch (err) {
    return (err as Error).stack;
  }
}

// ruleid: mcp-ts-error-stack-in-return
async function processRequest(input: string) {
  try {
    return eval(input);
  } catch (e) {
    return (e as Error).stack;
  }
}

// ruleid: mcp-ts-error-tostring-in-return
async function runQuery(sql: string) {
  try {
    return sql.toUpperCase();
  } catch (err) {
    return String(err);
  }
}

// ruleid: mcp-ts-error-tostring-in-return
async function fetchData(url: string) {
  try {
    const res = await fetch(url);
    return res.json();
  } catch (e) {
    return (e as Error).toString();
  }
}
