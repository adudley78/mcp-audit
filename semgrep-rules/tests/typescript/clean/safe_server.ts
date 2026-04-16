/**
 * Safe TypeScript MCP server — for Semgrep rule testing ONLY.
 * This file should produce zero findings when scanned with mcp-audit Semgrep rules.
 */

import { execFile, execFileSync } from "child_process";
import * as https from "https";
import * as fs from "fs";

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
