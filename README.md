# Zara Privacy MCP

A secure MCP (Model Context Protocol) server that sits between your AI agent and external services. It automatically detects and masks secrets and personal data so nothing sensitive leaks to LLM providers, databases, or APIs.

**What it does in one sentence:** Every call your AI agent makes through this MCP is automatically scanned and masked — API keys, passwords, emails, phone numbers, credit cards — zero leaks.

```
Your AI Agent
     │
     ▼  (stdio JSON-RPC)
┌──────────────────────┐
│  Zara Privacy MCP    │  ← auto-scans, masks, blocks dangerous ops
└──────────────────────┘
     │
     ▼
  Databases / APIs / AI Providers
```

---

## Why Use This?

| Problem | How Zara Solves It |
|---------|-------------------|
| AI agent accidentally sends your API key to an LLM | Auto-redacts secrets before sending, restores after |
| Someone queries `SELECT * FROM users` and leaks emails | Database results are auto-masked before returning |
| Agent tries `DROP TABLE` or `FLUSHALL` | Blocked by security gates — never executes |
| LLM provider goes down mid-session | Auto-fallback to next provider in chain |
| Token costs are too high | Compresses tool output before AI calls (20-40% savings) |

---

## Quick Start

### Prerequisites

- Go 1.21+ installed (for building from source)
- An MCP client (OpenCode, Kiro, Claude Code, or any MCP-compatible tool)

### Installation Options

**Option A: go install (recommended)**

```bash
go install github.com/aldok10/zara-privacy-mcp/cmd/server@latest
# Binary is installed to $GOPATH/bin/server — rename it:
mv $(go env GOPATH)/bin/server $(go env GOPATH)/bin/zara-privacy-mcp
```

**Option B: Download from GitHub Releases**

Download the latest pre-built binary for your OS:

| OS | Architecture | Download |
|----|-------------|----------|
| Linux | amd64 | [zara-privacy-mcp-linux-amd64](https://github.com/aldok10/zara-privacy-mcp/releases/latest) |
| macOS | arm64 (Apple Silicon) | [zara-privacy-mcp-darwin-arm64](https://github.com/aldok10/zara-privacy-mcp/releases/latest) |
| Windows | amd64 | [zara-privacy-mcp-windows-amd64.exe](https://github.com/aldok10/zara-privacy-mcp/releases/latest) |

```bash
# Example: Linux
curl -Lo zara-privacy-mcp https://github.com/aldok10/zara-privacy-mcp/releases/latest/download/zara-privacy-mcp-linux-amd64
chmod +x zara-privacy-mcp
sudo mv zara-privacy-mcp /usr/local/bin/
```

**Option C: Build from source**

```bash
git clone https://github.com/aldok10/zara-privacy-mcp.git
cd zara-privacy-mcp
make build
```

### 2. Set up your connections

```bash
cp .env.example .env
# Edit .env — add your database/API/AI credentials
```

### 3. Create a wrapper script

Edit `scripts/mcp-wrapper.sh` with your env vars:

```bash
#!/bin/sh
export ZARA_ENCRYPTION_KEY="pick-a-strong-passphrase-here!!"
export ZARA_DB_MYDB_DSN="postgres://user:pass@localhost:5432/mydb"
# Add more connections as needed...
exec /path/to/zara-privacy-mcp --stdio
```

```bash
chmod +x scripts/mcp-wrapper.sh
```

### 4. Register with your AI tool

Add to your tool's MCP config (e.g. `~/.config/opencode/opencode.json`):

```json
{
  "mcp": {
    "zara-privacy-mcp": {
      "type": "local",
      "command": ["/absolute/path/to/scripts/mcp-wrapper.sh"],
      "enabled": true
    }
  }
}
```

### 5. Restart your AI tool — done!

The 20 tools are now available to your agent. It can query databases, call APIs, and chat with AI providers — all through the privacy gateway.

### Verify it works

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | ./scripts/mcp-wrapper.sh 2>/dev/null \
  | python3 -c "import sys,json; print(f'{len(json.load(sys.stdin)[\"result\"][\"tools\"])} tools loaded')"
# Output: 20 tools loaded
```

---

## What's Included (20 Tools)

### Privacy Tools — scan and mask sensitive data
| Tool | What it does |
|------|-------------|
| `scan_context` | Finds secrets and PII in text, returns risk score |
| `redact_context` | Replaces sensitive data with `[EMAIL_1]`, `[API_KEY_1]` placeholders |
| `unredact_response` | Restores originals from placeholders after LLM responds |
| `compress_context` | Reduces token usage by deduplicating and stripping noise |
| `memory_filter` | Blocks high-risk data from being stored in agent memory |
| `classify_data` | Labels data as PUBLIC, INTERNAL, CONFIDENTIAL, or SECRET |
| `store_stats` | Shows how many placeholders are stored |

### Database Tools — query any database safely
| Tool | What it does |
|------|-------------|
| `db_query` | Runs SQL queries — results are auto-masked for PII |
| `db_list_tables` | Lists tables in a configured database |
| `db_describe` | Shows column names, types, and constraints |

Supports: PostgreSQL, MySQL, SQL Server, SQLite, Oracle, ClickHouse.

### MongoDB & Redis Tools
| Tool | What it does |
|------|-------------|
| `mongo_find` | Queries MongoDB collections — results auto-masked |
| `mongo_list_collections` | Lists collections |
| `redis_exec` | Runs Redis commands (GET, SET, HGETALL, etc.) |
| `redis_keys` | Lists keys matching a pattern |

### HTTP API Tools — safer alternative to curl
| Tool | What it does |
|------|-------------|
| `http_request` | Makes HTTP calls with auto-injected auth headers |
| `http_list_apis` | Shows configured API endpoints |

### AI Provider Tools — chat with any LLM privately
| Tool | What it does |
|------|-------------|
| `ai_chat` | Sends messages to AI — auto-redacts before, unredacts after |
| `ai_list_providers` | Shows available providers and models |
| `ai_quota_status` | Shows token usage and remaining quota |

9 free providers (Kiro, OpenCode, Codex, etc.) are pre-registered as fallback.

### Config
| Tool | What it does |
|------|-------------|
| `config_list` | Shows all active connections without exposing secrets |

---

## Configuration Reference

All configuration is through environment variables. Replace `<NAME>` with your own label (e.g. `PROD`, `STAGING`, `LOCAL`).

```bash
# === Required ===
ZARA_ENCRYPTION_KEY="your-passphrase-min-16-chars"

# === Database (add as many as you need) ===
ZARA_DB_<NAME>_DSN=postgres://user:pass@host:5432/db
ZARA_DB_<NAME>_DRIVER=postgres    # optional — auto-detected from DSN

# === MongoDB ===
ZARA_MONGO_<NAME>_URI=mongodb://user:pass@host:27017
ZARA_MONGO_<NAME>_DATABASE=mydb

# === Redis ===
ZARA_REDIS_<NAME>_ADDR=host:6379
ZARA_REDIS_<NAME>_PASSWORD=secret

# === HTTP API ===
ZARA_API_<NAME>_URL=https://api.example.com
ZARA_API_<NAME>_AUTH=bearer           # bearer, basic, header, or none
ZARA_API_<NAME>_AUTH_ENV=MY_TOKEN     # env var name holding the actual token

# === AI Provider ===
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com/v1
ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_KEY1,OPENAI_KEY2   # comma = round-robin pool
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini

# === Optional ===
ZARA_OBSERVE_URL=http://localhost:5080    # OpenObserve telemetry
ZARA_AUDIT_LOG=/var/log/zara-audit.log   # blocked operations log
```

---

## Security

Built to comply with [OWASP AISVS 1.0](https://github.com/OWASP/AISVS):

- **Dangerous SQL blocked**: DROP, TRUNCATE, ALTER, DELETE without WHERE
- **Dangerous Redis blocked**: FLUSHALL, SHUTDOWN, EVAL, CONFIG
- **MongoDB injection blocked**: $where, $expr, $function
- **SSRF protection**: blocks requests to private IPs (10.x, 192.168.x) and cloud metadata (169.254.169.254)
- **Rate limiting**: max 20 concurrent tool calls
- **Input size limits**: 1MB text, 10MB HTTP body
- **Timeouts**: 30s on all external calls
- **Panic recovery**: server never crashes from a bad tool call
- **Audit log**: every blocked operation is logged with timestamp and reason

---

## Development

```bash
make build          # Build binary (version injected from git)
make test           # Run all tests with race detection
make lint           # go vet + staticcheck
make smoke          # Quick end-to-end test
make build-linux    # Cross-compile for Linux
make build-darwin   # Cross-compile for macOS ARM
```

Hot-reload config without restart:
```bash
kill -HUP $(pgrep zara-privacy-mcp)
```

---

## How It Works (Under the Hood)

1. **Agent calls a tool** (e.g. `db_query`) via MCP stdio
2. **Security gate checks** — is this a dangerous operation? Block if yes.
3. **Execute** — run the query/request against the real service
4. **Mask results** — scan every string value for secrets (24 patterns) and PII (18 patterns), replace with masked versions
5. **Return to agent** — clean, safe response

For AI calls (`ai_chat`):
1. **Redact messages** — replace secrets/PII with `[PLACEHOLDER]` before sending
2. **Send to provider** — provider never sees original values
3. **Unredact response** — restore originals in the response back to agent

---

## Support

If this project is useful to you:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square)](https://sociabuzz.com/aldok10)

## License

MIT.
