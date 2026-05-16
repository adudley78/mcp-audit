/**
 * Safe TypeScript SDK singleton transport examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-sdk-singleton-transport.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { randomUUID } from "crypto";

declare const app: ReturnType<typeof express>;

// ok: mcp-sdk-singleton-transport — per-request instantiation inside async arrow function
app.post('/mcp', async (req: express.Request, res: express.Response) => {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
    const server = new McpServer({ name: "my-server", version: "1.0.0" });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
});

// ok: mcp-sdk-singleton-transport — instantiation inside a named async function
async function createAndConnect(req: express.Request, res: express.Response) {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
    const server = new McpServer({ name: "my-server", version: "1.0.0" });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
}

// ok: mcp-sdk-singleton-transport — instantiation inside a regular function
function setupServer(req: express.Request, res: express.Response) {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
    const server = new McpServer({ name: "my-server", version: "1.0.0" });
    server.connect(transport);
}
