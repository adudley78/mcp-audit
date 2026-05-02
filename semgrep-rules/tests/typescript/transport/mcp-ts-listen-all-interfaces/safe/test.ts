/**
 * Safe TypeScript listen-all-interfaces examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-express-listen-all
 * and mcp-ts-http-listen-all.
 */

import express from "express";
import * as http from "http";
import Fastify from "fastify";

const app = express();
const server = http.createServer(app);
const fastify = Fastify();

// ok: mcp-ts-express-listen-all — bound to localhost
app.listen(3000, "127.0.0.1");

// ok: mcp-ts-express-listen-all — bound to localhost
app.listen(8080, "127.0.0.1", () => {
  console.log("Listening on localhost");
});

// ok: mcp-ts-express-listen-all — bound to localhost
server.listen(3000, "127.0.0.1");

// ok: mcp-ts-http-listen-all — bound to localhost
fastify.listen({ host: "127.0.0.1", port: 3000 });

// ok: mcp-ts-http-listen-all — bound to localhost
server.listen({ host: "127.0.0.1", port: 8080 });

// ok: mcp-ts-express-listen-all — port only, no explicit host (defaults to localhost in most frameworks)
app.listen(3000);
