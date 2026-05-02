/**
 * Safe TypeScript missing-input-validation examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-no-type-check-before-use.
 */

import { z } from "zod";

declare function db_query(sql: string): unknown;
declare function exec(cmd: string): unknown;

const SearchSchema = z.object({ query: z.string() });

// ok: mcp-ts-no-type-check-before-use — Zod schema validates before use
async function handleSearch(args: Record<string, unknown>) {
  const { query } = SearchSchema.parse(args);
  return db_query(query);
}

// ok: mcp-ts-no-type-check-before-use — explicit typeof guard
async function handleExec(args: Record<string, unknown>) {
  if (typeof args["command"] === "string") {
    return exec(args["command"]);
  }
  throw new Error("command must be a string");
}

// ok: mcp-ts-no-type-check-before-use — static string, not a dynamic arg
async function handleStatic() {
  return db_query("SELECT 1");
}
