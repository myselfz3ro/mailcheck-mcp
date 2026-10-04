# MailCheck MCP

**Stop your cold emails from landing in spam — right inside Claude, Cursor, or any MCP client.**

MailCheck MCP gives your AI assistant two tools:

- **`check_domain`** — SPF / DKIM / DMARC / MX health for any sending domain, scored 0–4.
- **`check_copy`** — scans email subject+body for spam-trigger phrases, ALL-CAPS, and punctuation abuse, with a risk score.

Ask Claude *"is my domain set up to send cold email?"* or *"will this email hit spam?"* and get a real answer backed by live DNS lookups — no SaaS signup, no API key, no data leaving your machine.

## Why

Cold email silently dies in spam folders when auth (SPF/DKIM/DMARC) is misconfigured or the copy trips spam filters. We built this after our own 300-email campaign got 0 replies — turned out to be an auth/offer problem we couldn't see. Now you can see it before you hit send.

## Install

Requires **Node ≥ 18** and **Python 3** (used for the DNS/dig logic), plus `dig` (standard on macOS/Linux). No signup, no API key — nothing leaves your machine.

### Fastest — one line, no clone, no npm account

```json
{
  "mcpServers": {
    "mailcheck": {
      "command": "npx",
      "args": ["-y", "github:myselfz3ro/mailcheck-mcp"]
    }
  }
}
```

Drop that into your MCP client's config and restart. `npx` fetches and runs it directly from GitHub — that's the whole install.

### Or clone it

```bash
git clone https://github.com/myselfz3ro/mailcheck-mcp
cd mailcheck-mcp
npm run smoke   # verify it works
```

### Claude Desktop

Add the `npx` block above to `claude_desktop_config.json` (or, if cloned, point `command: "node"` at `/absolute/path/to/mailcheck-mcp/mcp/server.js`).

### Cursor / Windsurf / Zed

Point your MCP server config at `node /absolute/path/to/mailcheck-mcp/mcp/server.js` over stdio.

## Tools

| Tool | Input | Returns |
|------|-------|---------|
| `check_domain` | `domain` (string) | MX/SPF/DKIM/DMARC findings + `deliverability_score` 0–4 |
| `check_copy` | `text` (string) | spam triggers, ALL-CAPS, punctuation, `risk_level`, `risk_points` |

### Note on DKIM

DKIM selectors are provider-specific. If you send through Gmail/Google Workspace SMTP, Google signs your mail with **its own** key — a selector probe on your domain will report "not found" even though your mail **is** signed. In that case, trust an inbox-placement test over the selector check.

## License

MIT. Free. Tips welcome — [PayPal](https://paypal.me/) · star the repo if it saved you from the spam folder.
