/**
 * Vulnerable TypeScript SDK singleton transport examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains the CVE-2026-25536 vulnerability pattern.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { randomUUID } from "crypto";

declare const app: ReturnType<typeof express>;

// ruleid: mcp-sdk-singleton-transport
const server = new McpServer({ name: "my-server", version: "1.0.0" });

// ruleid: mcp-sdk-singleton-transport
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });

app.post('/mcp', async (req: express.Request, res: express.Response) => {
    // transport is reused across all clients — CVE-2026-25536
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
});

// ruleid: mcp-sdk-singleton-transport
let serverB = new McpServer({ name: "server-b", version: "2.0.0" });

// ruleid: mcp-sdk-singleton-transport
var transportB = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });

// ruleid: mcp-sdk-singleton-transport
let serverC = new McpServer({ name: "server-c", version: "3.0.0" });
