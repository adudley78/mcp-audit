/**
 * Vulnerable TypeScript MCP server examples — SQL injection.
 * For Semgrep rule testing ONLY. DO NOT deploy this code.
 */

import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// --- String concatenation SQL injection ---

async function getUserById(userId: string): Promise<unknown> {
  // ruleid: mcp-ts-string-concat-sql
  return pool.query("SELECT * FROM users WHERE id = " + userId);
}

async function searchUsers(name: string): Promise<unknown> {
  const db = pool;
  // ruleid: mcp-ts-string-concat-sql
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

async function deleteRecord(table: string, id: string): Promise<unknown> {
  // ruleid: mcp-ts-string-concat-sql
  return pool.query("DELETE FROM " + table + " WHERE id = " + id);
}

// --- Template literal SQL injection ---

async function getOrdersByUser(userId: string): Promise<unknown> {
  // ruleid: mcp-ts-template-literal-sql
  return pool.query(`SELECT * FROM orders WHERE user_id = ${userId}`);
}

async function updateUserEmail(userId: string, email: string): Promise<unknown> {
  const client = await pool.connect();
  // ruleid: mcp-ts-template-literal-sql
  return client.query(`UPDATE users SET email = '${email}' WHERE id = ${userId}`);
}
