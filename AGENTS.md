# Zara Privacy MCP — Agent Instructions

**Privacy-first MCP gateway.** 19 tools: privacy layer + database proxy (SQL/MongoDB/Redis) + HTTP API proxy + AI provider proxy — all with automatic data masking.

Data flow: `Agent → MCP (stdio) → DB/HTTP/AI call → auto-mask → Agent`

## Architecture

```
OpenCode / Kiro
   │  MCP (stdio)
   ▼
Zara Privacy MCP
   │
   ├── Privacy Layer (always on)
   │   ├── scan/redact/unredact secrets & PII
   │   ├── context compression
   │   ├── memory filter
   │   └── data classification
   │
   ├── Database Proxy
   │   ├── SQL: PostgreSQL, MySQL, SQL Server, SQLite, Oracle, ClickHouse
   │   ├── MongoDB: find, list collections
   │   ├── Redis: exec commands, key listing
   │   ├── Auto-detect driver from DSN
   │   └── All results auto-masked
   │
   ├── HTTP API Proxy
   │   ├── Auth injection from env (bearer, basic, header)
   │   └── Response auto-masked
   │
   └── AI Provider Proxy
       ├── OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, Groq
       ├── Auto-redact before send
       └── Auto-unredact after response
```

## Project Structure

```
cmd/server/main.go           — Entry point
config/config.go             — Env-based configuration
internal/
├── detector/                — Secret (21 patterns) + PII (15 patterns) detection
├── engine/                  — Redact/unredact pipeline
├── crypto/                  — AES-256-GCM encryption
├── store/                   — Encrypted SQLite mapping store
├── compress/                — Context compression (dedup, TF-IDF)
├── classify/                — Sensitivity classification
├── metrics/                 — Prometheus metrics
├── observe/                 — OpenObserve telemetry
├── db/                      — SQL + MongoDB + Redis proxy with auto-masking
├── http/                    — HTTP API proxy with auto-masking
├── ai/                      — AI provider proxy with auto-redact/unredact
└── mcp/server.go            — MCP server, JSON-RPC, tool dispatch
```

## 19 MCP Tools

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
| `http_request` | HTTP call with auto auth + response masking |
| `http_list_apis` | List configured endpoints |

### AI Provider (2)
| Tool | Description |
|------|-------------|
| `ai_chat` | Chat with LLM, auto redact/unredact |
| `ai_list_providers` | List providers + models |

### Config (1)
| Tool | Description |
|------|-------------|
| `config_list` | Show all connections (no secrets exposed) |

## Configuration (env vars)

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

# AI Provider
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com/v1
ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini
```

## Install for OpenCode / Kiro

### Step 1: Build

```bash
cd /path/to/zara-privacy-mcp
make build
```

### Step 2: Setup .env

```bash
cp .env.example .env
```

Edit `.env` with your actual connections:

```bash
# Required
ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-32-chars"

# SQL Database
ZARA_DB_PROD_DRIVER=postgres
ZARA_DB_PROD_DSN=postgres://user:pass@host:5432/mydb?sslmode=disable

# MongoDB
ZARA_MONGO_APP_URI=mongodb://user:pass@host:27017
ZARA_MONGO_APP_DATABASE=myapp

# Redis
ZARA_REDIS_CACHE_ADDR=host:6379
ZARA_REDIS_CACHE_PASSWORD=secret
ZARA_REDIS_CACHE_DB=0

# HTTP API
ZARA_API_GITHUB_URL=https://api.github.com
ZARA_API_GITHUB_AUTH=bearer
ZARA_API_GITHUB_AUTH_ENV=GITHUB_TOKEN

# AI Provider
ZARA_AI_OPENAI_BASE_URL=https://api.openai.com/v1
ZARA_AI_OPENAI_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_OPENAI_MODELS=gpt-4o,gpt-4o-mini
```

### Step 3: Setup wrapper script

Edit `scripts/mcp-wrapper.sh` — add all env vars from your `.env`:

```bash
#!/bin/sh
export ZARA_ENCRYPTION_KEY="your-key-here"
export ZARA_DB_PROD_DRIVER=postgres
export ZARA_DB_PROD_DSN="postgres://user:pass@host:5432/mydb"
# ... all your vars
exec /absolute/path/to/zara-privacy-mcp --stdio
```

```bash
chmod +x scripts/mcp-wrapper.sh
```

### Step 4: Register in OpenCode / Kiro

Add to `~/.config/opencode/opencode.json`:

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

### Step 5: Restart and verify

Restart OpenCode/Kiro. Verify:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | /path/to/scripts/mcp-wrapper.sh 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d[\"result\"][\"tools\"])} tools loaded')"
```

### Optional: Install globally

```bash
sudo make install        # Binary to /usr/local/bin
make install-skill       # Skill to ~/.agents/skills/ and ~/.claude/skills/
```

## MCP Protocol

Supports both method formats:
- `tools/list` / `tools/call` (MCP spec)
- `list_tools` / `call_tool` (legacy)

Handles `notifications/initialized` silently (no response).

## Important

- All masking is automatic — agent does not need to explicitly mask
- Credentials never appear in prompts — auth injected from env by MCP
- Privacy tools always ready (only need `ZARA_ENCRYPTION_KEY`)
- DB/API/AI tools need env var configuration
- Hot reload: `kill -HUP` to reload config without restart
- Transport: `--stdio` for MCP clients, HTTP POST `/mcp` for testing
