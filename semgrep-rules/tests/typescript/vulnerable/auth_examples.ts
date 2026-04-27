/**
 * Vulnerable TypeScript MCP server auth examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities
 * mapping to CVE-2026-33032 (MCPwn) and CVE-2026-41495 (n8n-MCP log exposure).
 */

import express, { Request, Response, NextFunction } from "express";

const app = express();
const router = express.Router();

// ---------------------------------------------------------------------------
// Asymmetric auth routes — MCPwn (CVE-2026-33032) pattern
// ---------------------------------------------------------------------------

function verifyToken(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers["authorization"];
  if (!token) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

async function mcpMessageHandler(req: Request, res: Response): Promise<void> {
  res.json({ status: "ok" });
}

// Safe sibling — auth middleware present (should NOT be flagged)
app.get("/mcp", verifyToken, mcpMessageHandler);

// ruleid: mcp-ts-route-missing-auth-middleware
// Vulnerable leg — same handler, no auth middleware in the call
app.get("/mcp_message", mcpMessageHandler);

// ruleid: mcp-ts-route-missing-auth-middleware
// Well-known discovery endpoint without auth
app.get("/.well-known/mcp-manifest", mcpMessageHandler);

// ruleid: mcp-ts-route-missing-auth-middleware
router.post("/mcp_execute", mcpMessageHandler);

// ---------------------------------------------------------------------------
// Authorization headers logged (CVE-2026-41495)
// ---------------------------------------------------------------------------

// ruleid: mcp-ts-auth-header-logged
function logRequestDetails(req: Request): void {
  console.log(req.headers); // logs Authorization, x-api-key, etc.
}

// ruleid: mcp-ts-auth-header-logged
function traceRequest(req: Request): void {
  console.log(JSON.stringify(req.headers));
}

// ruleid: mcp-ts-auth-header-logged
function debugMiddleware(req: Request, res: Response, next: NextFunction): void {
  console.log(`Incoming request headers: ${req.headers}`);
  next();
}

// ruleid: mcp-ts-auth-header-logged
import winston from "winston";
const logger = winston.createLogger({ level: "debug" });

function winstonHeaderLog(req: Request): void {
  logger.debug(req.headers); // logger instance — also flagged
}
