#!/usr/bin/env node
/**
 * MailCheck MCP Server
 * ---------------------
 * Exposes cold-email deliverability checks to any MCP client
 * (Claude Desktop, Cursor, Windsurf, Zed, etc.) over stdio.
 *
 * Tools:
 *   check_domain  - SPF/DKIM/DMARC/MX health for a sending domain
 *   check_copy    - spam-trigger / ALL-CAPS / punctuation risk scan of email copy
 *
 * Zero npm dependencies: speaks the MCP JSON-RPC 2.0 stdio protocol directly
 * and reuses the proven Python mailcheck logic as the single source of truth.
 */
"use strict";
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const PY = process.env.MAILCHECK_PY || "python3";
// mailcheck.py sits next to this file under ../src after install; resolve robustly.
const SRC = path.resolve(__dirname, "..", "src");

function runPython(fn, arg) {
  const code = `
import sys, json
sys.path.insert(0, ${JSON.stringify(SRC)})
import mailcheck
arg = json.loads(sys.stdin.read())["arg"]
print(json.dumps(getattr(mailcheck, ${JSON.stringify(fn)})(arg)))
`;
  const res = spawnSync(PY, ["-c", code], {
    input: JSON.stringify({ arg }),
    encoding: "utf8",
    timeout: 20000,
  });
  if (res.status !== 0) {
    throw new Error((res.stderr || "python error").trim().slice(0, 500));
  }
  return JSON.parse(res.stdout.trim());
}

const TOOLS = [
  {
    name: "check_domain",
    description:
      "Check a sending domain's cold-email deliverability health: MX, SPF, DKIM, DMARC. Returns a 0-4 score and the raw DNS findings. Use before running any cold-email campaign.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain to check, e.g. example.com" },
      },
      required: ["domain"],
    },
  },
  {
    name: "check_copy",
    description:
      "Scan email subject+body text for spam triggers: known spam-trigger phrases, excessive ALL-CAPS, and excessive punctuation. Returns a risk level and point score. Use to vet email copy before sending.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "The email subject and/or body to scan" },
      },
      required: ["text"],
    },
  },
];

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function handle(msg) {
  const { id, method, params } = msg;
  try {
    if (method === "initialize") {
      return send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "mailcheck", version: "1.0.0" },
        },
      });
    }
    if (method === "tools/list") {
      return send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    }
    if (method === "tools/call") {
      const name = params && params.name;
      const args = (params && params.arguments) || {};
      let data;
      if (name === "check_domain") data = runPython("check_domain", String(args.domain || ""));
      else if (name === "check_copy") data = runPython("check_copy", String(args.text || ""));
      else throw new Error("unknown tool: " + name);
      return send({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] },
      });
    }
    if (method === "notifications/initialized" || (method && method.startsWith("notifications/"))) {
      return; // no response to notifications
    }
    // unknown method
    if (id !== undefined) {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: "method not found: " + method } });
    }
  } catch (e) {
    if (id !== undefined) {
      send({ jsonrpc: "2.0", id, error: { code: -32000, message: String(e.message || e) } });
    }
  }
}

// --- stdio line-delimited JSON-RPC loop ---
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    handle(msg);
  }
});
process.stdin.on("end", () => process.exit(0));
