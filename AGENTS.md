# Zara Privacy MCP — Agent Instructions

**Privacy-first MCP gateway.** 20 tools: privacy layer + database proxy (SQL/MongoDB/Redis) + HTTP API proxy + AI provider proxy — all with automatic data masking.

Data flow: `Agent → MCP (stdio) → DB/HTTP/AI call → auto-mask → Agent`

## Skills

This project includes these skills in `.opencode/skills/`:

- **`zara-privacy-mcp`** — MCP tool usage, query DNA, security shield, OWASP AISVS compliance
- **`golang-expert`** — Go best practices, patterns, concurrency, testing, security

## Architecture

```
cmd/server/main.go                — Entry point (runfx/fx lifecycle)
internal/bootstrap/               — DI wiring (fx.Module, lifecycle hooks)
transport/server.go               — mcp-go server, 20 tools, middleware
application/tools/                — Tool handlers + security validators
domain/                           — Interfaces, strategies, errors
internal/
├── ai/                           — AI provider proxy + router + fallback + quota + format
├── db/                           — SQL + MongoDB + Redis proxy with auto-masking
├── http/                         — HTTP API proxy with SSRF protection + retry
├── detector/                     — Secret (21 patterns) + PII (18 patterns)
├── engine/                       — Redact/unredact pipeline
├── masking/                      — Shared mask helper (eliminates duplication)
├── store/                        — Encrypted SQLite mapping store
├── crypto/                       — AES-256-GCM encryption
├── observe/                      — OpenObserve telemetry
├── audit/                        — File-based audit logging
└── version/                      — Build-time version injection
config/                           — Env-based config + validation + SIGHUP reload
```

## 20 MCP Tools

### Privacy (7)
| Tool | Description |
|------|-------------|
| `scan_context` | Detect secrets + PII, return risk score |
| `redact_context` | Replace sensitive data with `[PLACEHOLDER]` |
| `unredact_response` | Restore original values from LLM response |
| `compress_context` | Dedup, strip comments, extract key sections |
| `memory_filter` | Block high-risk data from memory |
| `classify_data` | Assign sensitivity label |
| `store_stats` | Mapping store statistics |

### SQL Database (3)
| Tool | Description |
|------|-------------|
| `db_query` | Execute SQL, results auto-masked |
| `db_list_tables` | List all tables |
| `db_describe` | Show column schema |

### MongoDB (2)
| Tool | Description |
|------|-------------|
| `mongo_find` | Query documents, results auto-masked |
| `mongo_list_collections` | List collections |

### Redis (2)
| Tool | Description |
|------|-------------|
| `redis_exec` | Execute any Redis command, results auto-masked |
| `redis_keys` | List keys by pattern |

### HTTP API (2)
| Tool | Description |
|------|-------------|
| `http_request` | HTTP call with auto auth + retry + response masking |
| `http_list_apis` | List configured endpoints |

### AI Provider (3)
| Tool | Description |
|------|-------------|
| `ai_chat` | Chat with LLM, auto redact/unredact, fallback routing |
| `ai_list_providers` | List providers + models |
| `ai_quota_status` | Show quota usage + provider stats |

### Config (1)
| Tool | Description |
|------|-------------|
| `config_list` | Show all connections (no secrets exposed) |

## Configuration

```bash
# Required
ZARA_ENCRYPTION_KEY="min-16-chars"

# SQL Database (driver auto-detected from DSN)
ZARA_DB_<NAME>_DSN=postgres://user:pass@host:5432/db
ZARA_DB_<NAME>_DRIVER=postgres|mysql|sqlserver|sqlite|oracle|clickhouse

# MongoDB
ZARA_MONGO_<NAME>_URI=mongodb://host:27017
ZARA_MONGO_<NAME>_DATABASE=mydb

# Redis
ZARA_REDIS_<NAME>_ADDR=host:6379
ZARA_REDIS_<NAME>_PASSWORD=secret
ZARA_REDIS_<NAME>_DB=0

# HTTP API
ZARA_API_<NAME>_URL=https://api.example.com
ZARA_API_<NAME>_AUTH=bearer|basic|header|none
ZARA_API_<NAME>_AUTH_ENV=TOKEN_VAR_NAME

# AI Provider (comma-separated keys for pool round-robin)
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com/v1
ZARA_AI_<NAME>_API_KEY_ENV=KEY1,KEY2,KEY3
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini

# Observability
ZARA_OBSERVE_URL=http://localhost:5080
ZARA_OBSERVE_USER=root@example.com
ZARA_OBSERVE_KEY=api-key
ZARA_OBSERVE_STREAM=zara-mcp

# Audit
ZARA_AUDIT_LOG=/path/to/audit.log
```

## Install

### Step 1: Build

```bash
make build
```

### Step 2: Setup wrapper script

Edit `scripts/mcp-wrapper.sh` with your env vars:

```bash
#!/bin/sh
export ZARA_ENCRYPTION_KEY="your-key"
export ZARA_DB_PROD_DSN="postgres://..."
exec /path/to/zara-privacy-mcp --stdio
```

### Step 3: Register in OpenCode / Kiro

```json
{
  "mcp": {
    "zara-privacy-mcp": {
      "type": "local",
      "command": ["/path/to/scripts/mcp-wrapper.sh"],
      "enabled": true
    }
  }
}
```

### Step 4: Verify

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | /path/to/scripts/mcp-wrapper.sh 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d[\"result\"][\"tools\"])} tools loaded')"
```

## Key Features

- **Auto-fallback AI routing** — if primary provider fails, tries next in chain (9 free providers pre-registered)
- **Multi-account pool** — comma-separated API keys round-robin automatically
- **RTK token compression** — tool_result messages compressed before AI calls (saves 20-40%)
- **Quota tracking** — per-provider token limits with configurable reset periods
- **Format translation** — OpenAI ↔ Anthropic ↔ Gemini native formats
- **SSRF protection** — blocks private IPs, cloud metadata endpoints
- **Security gates** — blocks DROP/TRUNCATE, FLUSHALL, $where, DELETE without WHERE
- **HTTP retry** — exponential backoff (3 attempts) for 5xx errors
- **Config hot-reload** — `kill -HUP` re-reads env vars
- **Audit logging** — blocked operations written to file
- **Version tagging** — git tag + commit hash in MCP initialize response

## MCP Protocol

Supports both method formats:
- `tools/list` / `tools/call` (MCP spec)
- Legacy: `list_tools` / `call_tool`

Transport: `--stdio` for MCP clients. Built on [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go).
