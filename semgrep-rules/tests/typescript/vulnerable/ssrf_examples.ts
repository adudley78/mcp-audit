/**
 * Vulnerable TypeScript MCP server examples — SSRF.
 * For Semgrep rule testing ONLY. DO NOT deploy this code.
 */

import axios from "axios";
import * as https from "https";
import * as http from "http";
import * as net from "net";
import ipaddr from "ipaddr.js";

// --- fetch() SSRF ---

async function fetchUserUrl(userUrl: string): Promise<unknown> {
  // ruleid: mcp-ts-fetch-ssrf
  const response = await fetch(userUrl);
  return response.json();
}

// --- axios SSRF ---

async function proxyRequest(targetUrl: string): Promise<unknown> {
  // ruleid: mcp-ts-fetch-ssrf
  return axios.get(targetUrl);
}

async function postToUrl(url: string, data: unknown): Promise<unknown> {
  // ruleid: mcp-ts-fetch-ssrf
  return axios.post(url, data);
}

async function axiosGeneric(endpoint: string): Promise<unknown> {
  // ruleid: mcp-ts-fetch-ssrf
  return axios(endpoint);
}

// --- https/http.request() SSRF ---

function httpGetUnsafe(targetUrl: string): void {
  // ruleid: mcp-ts-http-request-ssrf
  https.get(targetUrl, (res) => {
    res.resume();
  });
}

function httpRequestUnsafe(url: string): void {
  // ruleid: mcp-ts-http-request-ssrf
  http.request(url, (res) => {
    res.resume();
  });
}

// --- SSRF: tool argument URL (CVE-2026-44284, CVE-2026-39974, CVE-2026-27826) ---

async function fetchFromArgsDirect(args: { url: string }): Promise<unknown> {
  // ruleid: mcp-ts-tool-arg-url-ssrf
  const response = await fetch(args.url);
  return response.json();
}

async function fetchFromArgsEndpoint(args: { endpoint: string }): Promise<unknown> {
  // ruleid: mcp-ts-tool-arg-url-ssrf
  const response = await fetch(args.endpoint);
  return response.json();
}

async function axiosFromArgs(args: { url: string }): Promise<unknown> {
  // ruleid: mcp-ts-tool-arg-url-ssrf
  return axios.get(args.url);
}

async function fetchViaIntermediate(args: { url: string }): Promise<unknown> {
  // ruleid: mcp-ts-tool-arg-url-ssrf
  const target = args.url;
  return fetch(target);
}

// --- SSRF: request header as HTTP call target (CVE-2026-39974, CVE-2026-27826) ---

async function proxyViaHeader(req: Request): Promise<unknown> {
  // ruleid: mcp-ts-request-header-ssrf
  const targetUrl = (req.headers as Record<string, string>)["x-target-url"];
  const response = await fetch(targetUrl);
  return response.json();
}

async function proxyViaHeaderProp(req: { headers: { targetUrl: string } }): Promise<unknown> {
  // ruleid: mcp-ts-request-header-ssrf
  const response = await fetch(req.headers.targetUrl);
  return response.json();
}

// --- SSRF: guard that only blocks IP literals (Wazuh MCP, GHSA-pw2j-pj4h-f5vg) ---
// net.isIP() is 0 for a hostname and ipaddr.parse() throws on one; each guard
// below then lets the hostname through without resolving it.

function isPrivateHost(host: string): boolean {
  // ruleid: mcp-ts-ssrf-ip-literal-only-guard
  if (!net.isIP(host)) return false;
  return /^(10\.|127\.|169\.254\.|192\.168\.)/.test(host);
}

async function fetchWithLiteralGuard(target: string): Promise<unknown> {
  const host = new URL(target).hostname;
  // ruleid: mcp-ts-ssrf-ip-literal-only-guard
  if (net.isIP(host) && isPrivateIp(host)) {
    throw new Error("internal address");
  }
  // ruleid: mcp-ts-fetch-ssrf
  return fetch(target);
}

const isInternalAddress = (host: string): boolean => {
  try {
    // ruleid: mcp-ts-ssrf-ip-literal-only-guard
    return ipaddr.parse(host).range() !== "unicast";
  } catch {
    return false;
  }
};

function isPrivateIp(ip: string): boolean {
  return ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("169.254.");
}
