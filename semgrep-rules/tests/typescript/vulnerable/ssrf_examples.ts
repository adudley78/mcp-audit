/**
 * Vulnerable TypeScript MCP server examples — SSRF.
 * For Semgrep rule testing ONLY. DO NOT deploy this code.
 */

import axios from "axios";
import * as https from "https";
import * as http from "http";

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
