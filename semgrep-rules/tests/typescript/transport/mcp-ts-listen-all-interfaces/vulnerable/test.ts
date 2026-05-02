/**
 * Vulnerable TypeScript listen-all-interfaces examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

import express from "express";
import * as http from "http";
import Fastify from "fastify";

const app = express();
const server = http.createServer(app);
const fastify = Fastify();

// ruleid: mcp-ts-express-listen-all
app.listen(3000, "0.0.0.0");

// ruleid: mcp-ts-express-listen-all
app.listen(8080, "0.0.0.0", () => {
  console.log("Listening");
});

// ruleid: mcp-ts-express-listen-all
server.listen(3000, "0.0.0.0");

// ruleid: mcp-ts-http-listen-all
fastify.listen({ host: "0.0.0.0", port: 3000 });

// ruleid: mcp-ts-http-listen-all
server.listen({ host: "0.0.0.0", port: 8080 });

// ruleid: mcp-ts-express-listen-all
app.listen(9000, "");
