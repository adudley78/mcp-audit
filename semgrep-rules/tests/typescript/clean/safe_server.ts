/**
 * Safe TypeScript MCP server — for Semgrep rule testing ONLY.
 * This file should produce zero findings when scanned with mcp-audit Semgrep rules.
 */

import { execFile, execFileSync } from "child_process";
import * as https from "https";
import * as http from "http";
import * as fs from "fs";
import * as path from "path";
import { Pool } from "pg";
import axios from "axios";

// Safe: credentials from environment variables
const apiKey = process.env.API_KEY ?? "";
const secret = process.env.SECRET_TOKEN ?? "";

// Safe: execFile with array args (not exec with string)
async function runCommandSafe(filename: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("ls", ["-la", filename], (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// Safe: exec with string literal (not variable)
async function runStaticCommand(): Promise<string> {
  const { exec } = await import("child_process");
  return new Promise((resolve, reject) => {
    exec("ls -la /tmp", (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// Safe: eval with string literal
async function evaluateStatic(): Promise<number> {
  return eval("1 + 1"); // nosemgrep: mcp-ts-eval-variable
}

// Safe: https server (not http)
const tlsOptions = {
  cert: fs.readFileSync("/certs/cert.pem"),
  key: fs.readFileSync("/certs/key.pem"),
};
const secureServer = https.createServer(tlsOptions, (req, res) => {
  res.end("Secure MCP server");
});

// Safe: descriptive tool description
const safeTool = {
  name: "search",
  description: "Searches the filesystem for files matching the given pattern",
};

// Safe: short variable values (under threshold)
const tag = "v1";
const env = "prod";

// ── Path traversal safe patterns ──────────────────────────────────────────────

const BASE_DIR = "/app/data";

// Safe: path.resolve inline — excluded by pattern-not in mcp-ts-fs-readfile-traversal
async function readFileSafe(userInput: string): Promise<string> {
  return new Promise((resolve, reject) => {
    fs.readFile(path.resolve(BASE_DIR, userInput), "utf8", (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

// Safe: path.resolve inline — excluded by pattern-not in mcp-ts-fs-writefile-traversal
function writeFileSafe(userInput: string, content: string): void {
  fs.writeFile(path.resolve(BASE_DIR, userInput), content, () => {});
}

// Safe: static string path (no variable argument)
function readStaticConfig(): string {
  return fs.readFileSync("/etc/app/config.json", "utf8");
}

// Safe: path.join with all-string-literal args (excluded by pattern-not)
function buildStaticPath(): string {
  return path.join("/app", "assets", "logo.png");
}

// ── SQL safe patterns ─────────────────────────────────────────────────────────

const dbPool = new Pool({ connectionString: process.env.DATABASE_URL });

// Safe: first arg is a string literal with placeholder syntax
async function getUserSafe(userId: string): Promise<unknown> {
  return dbPool.query("SELECT * FROM users WHERE id = $1", [userId]);
}

// Safe: parameterized INSERT
async function insertUserSafe(name: string, email: string): Promise<unknown> {
  return dbPool.query("INSERT INTO users (name, email) VALUES ($1, $2)", [name, email]);
}

// ── SSRF safe patterns ────────────────────────────────────────────────────────

// Safe: fetch with string literal URL (excluded by pattern-not)
async function fetchStaticEndpoint(): Promise<unknown> {
  const response = await fetch("https://api.example.com/health");
  return response.json();
}

// Safe: axios with string literal URL (excluded by pattern-not)
async function axiosStaticCall(): Promise<unknown> {
  return axios.get("https://api.example.com/data");
}

// Safe: https.get with string literal URL (excluded by pattern-not)
function httpsStaticGet(): void {
  https.get("https://api.example.com/status", (res) => {
    res.resume();
  });
}
