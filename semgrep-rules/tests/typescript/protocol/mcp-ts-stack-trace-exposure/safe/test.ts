/**
 * Safe TypeScript stack-trace-exposure examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-error-stack-in-return
 * and mcp-ts-error-tostring-in-return.
 */

// ok: mcp-ts-error-stack-in-return — generic error message returned, stack logged server-side
async function handleTool(args: unknown) {
  try {
    return JSON.parse(args as string);
  } catch (err) {
    console.error("Parse failed:", (err as Error).message);
    return { error: "Invalid input format" };
  }
}

// ok: mcp-ts-error-tostring-in-return — sanitised error message, not raw exception string
async function runQuery(sql: string) {
  try {
    return sql.toUpperCase();
  } catch {
    return { error: "Query execution failed" };
  }
}

// ok: mcp-ts-error-stack-in-return — not inside an async function, stack used server-side only
function syncHelper() {
  try {
    throw new Error("test");
  } catch (err) {
    console.error((err as Error).stack);
    return null;
  }
}
