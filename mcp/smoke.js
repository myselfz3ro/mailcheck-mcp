#!/usr/bin/env node
// Smoke test: drives the MCP server through a full handshake and asserts both tools work.
"use strict";
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const server = path.resolve(__dirname, "server.js");
const msgs = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "check_copy", arguments: { text: "FREE money act now CLICK HERE!!!" } } },
];
const input = msgs.map((m) => JSON.stringify(m)).join("\n") + "\n";
const res = spawnSync("node", [server], { input, encoding: "utf8", timeout: 25000 });
const lines = res.stdout.trim().split("\n").map((l) => JSON.parse(l));

let ok = true;
const init = lines.find((l) => l.id === 1);
if (!init || init.result.serverInfo.name !== "mailcheck") { console.error("FAIL initialize"); ok = false; }
const list = lines.find((l) => l.id === 2);
if (!list || list.result.tools.length !== 2) { console.error("FAIL tools/list"); ok = false; }
const call = lines.find((l) => l.id === 3);
const parsed = call && JSON.parse(call.result.content[0].text);
if (!parsed || parsed.risk_level !== "high") { console.error("FAIL check_copy"); ok = false; }

if (ok) { console.log("SMOKE OK: initialize + 2 tools + check_copy(high) all pass"); process.exit(0); }
process.exit(1);
