/**
 * Vulnerable TypeScript MCP server examples — path traversal.
 * For Semgrep rule testing ONLY. DO NOT deploy this code.
 */

import * as fs from "fs";
import * as path from "path";

// --- fs.readFile path traversal ---

async function readUserFile(filename: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // ruleid: mcp-ts-fs-readfile-traversal
    fs.readFile(filename, "utf8", (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

function readFileSyncUnsafe(filePath: string): string {
  // ruleid: mcp-ts-fs-readfile-traversal
  return fs.readFileSync(filePath, "utf8");
}

// --- fs.writeFile path traversal ---

async function writeUserFile(filename: string, data: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // ruleid: mcp-ts-fs-writefile-traversal
    fs.writeFile(filename, data, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function appendSyncUnsafe(filePath: string, content: string): void {
  // ruleid: mcp-ts-fs-writefile-traversal
  fs.appendFileSync(filePath, content);
}

// --- path.join without boundary check ---

function buildFilePath(baseDir: string, userInput: string): string {
  // ruleid: mcp-ts-path-join-traversal
  return path.join(baseDir, userInput);
}
