# Zara Secure MCP

**General-purpose secure gateway for OpenCode.** Privacy layer + database proxy + HTTP API proxy + AI provider proxy — all with automatic data masking.

Data flow: `Agent → MCP → DB/HTTP/AI call → masking → agent`

> 🔒 **Every outbound call is automatically masked.** Secrets, PII, and credentials never leak to external services.

> 🔒 **Your data, your control.** Zero secrets leak to third-party LLM providers.

---

## Why

Every time you paste context into an LLM prompt, you risk leaking:

- **API keys** (OpenAI, Anthropic, Gemini, AWS, etc.)
- **Database credentials** (PostgreSQL, MongoDB, Redis)
- **JWT tokens, bearer tokens, session cookies**
- **PII** — emails, phone numbers, KTP, NPWP, NRIC, credit cards
- **Private keys** (SSH, PEM, certificates)

Zara Privacy MCP intercepts context before it reaches the LLM, replaces sensitive values with reversible placeholders, then restores the originals in the response. The mapping table is encrypted with **AES-256-GCM** and stored in SQLite — only you have the key.

---

## Architecture

```
OpenCode (AI Client)
   │  MCP (stdio or HTTP)
   ▼
Zara Secure MCP
   │
   ├── Privacy Layer (always on)
   │   ├── scan/redact/unredact secrets & PII
   │   ├── context compression
   │   ├── memory filter
   │   └── data classification
   │
    ├── Database Proxy
    │   ├── PostgreSQL, MySQL, MariaDB, SQL Server, SQLite
    │   ├── Auto-detect driver from DSN
    │   ├── Auto-mask query results
    │   └── Schema discovery
   │
   ├── HTTP API Proxy
   │   ├── Configured endpoints with auth
   │   ├── Auto-mask responses
   │   └── Safer curl alternative
   │
   └── AI Provider Proxy
       ├── OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter
       ├── Auto-redact before send
       └── Auto-unredact after response
```

---

## 15 MCP Tools

### Privacy (7)
| Tool | What It Does |
|------|-------------|
| `scan_context` | Detect secrets + PII. Returns risk score + findings. No modification. |
| `redact_context` | Replace sensitive data with `[PLACEHOLDER_N]` tokens. |
| `unredact_response` | Restore original values from LLM responses. |
| `compress_context` | Dedup, remove comments, extract key sections. Save tokens. |
| `memory_filter` | Validate memory before persistence. Block high-risk data. |
| `classify_data` | Assign sensitivity label (PUBLIC → SECRET). |
| `store_stats` | Get mapping store statistics. |

### Database (3)
| Tool | What It Does |
|------|-------------|
| `db_query` | Execute SQL query (PostgreSQL, MySQL, MariaDB, SQL Server, SQLite). Results auto-scanned and masked. |
| `db_list_tables` | List all tables in a database. |
| `db_describe` | Show column schema for a table. |

### HTTP API (2)
| Tool | What It Does |
|------|-------------|
| `http_request` | Make API call with auto auth + response masking. Safer curl. |
| `http_list_apis` | List configured API endpoints. |

### AI Provider (2)
| Tool | What It Does |
|------|-------------|
| `ai_chat` | Chat with LLM. Auto-redacts prompt, auto-unredacts response. |
| `ai_list_providers` | List configured AI providers + models. |

### Config (1)
| Tool | What It Does |
|------|-------------|
| `config_list` | Show all configured databases, APIs, and AI providers. |

---

## Quick Start

### Prerequisites

- Go 1.21+
- No CGo required (pure Go SQLite via `modernc.org/sqlite`)

### 1. Build

```bash
make build
# Produces ./zara-privacy-mcp binary
```

### 2. Configure connections (optional)

Set any of these env vars to enable additional tools:

```bash
# Database (supported: postgres, mysql, mariadb, sqlserver, sqlite)
export ZARA_DB_PROD_DRIVER=postgres
export ZARA_DB_PROD_DSN=postgres://user:pass@host:5432/db

# Alternative: auto-detect driver from DSN (no need to set DRIVER)
export ZARA_DB_AUTO_DSN=mysql://user:pass@host:3306/db  # → auto-detected as mysql

# HTTP API
export ZARA_API_GITHUB_URL=https://api.github.com
export ZARA_API_GITHUB_AUTH=bearer
export ZARA_API_GITHUB_AUTH_ENV=GITHUB_TOKEN

# AI Provider
export ZARA_AI_OPENAI_BASE_URL=https://api.openai.com
export ZARA_AI_OPENAI_API_KEY_ENV=OPENAI_API_KEY
export ZARA_AI_OPENAI_MODELS=gpt-4o,gpt-4o-mini

# Required for privacy tools
export ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-16-chars"
```

### 3. Run (HTTP mode — for testing with Postman)

```bash
make run-dev
# Server starts on http://127.0.0.1:8530/mcp
```

### 4. Run (Stdio mode — for OpenCode integration)

```bash
make build
./zara-privacy-mcp --stdio
```

### 5. Install

```bash
make install
# Binary installed to /usr/local/bin/zara-privacy-mcp
```

### 6. Test

```bash
make test
# or
go test -v -count=1 ./...
```

### 7. Smoke test

```bash
make smoke
```

---

## Database Proxy

Configure via env vars. **Driver auto-detection** — no need to set DRIVER if your DSN uses a standard format.

```bash
# PostgreSQL (explicit)
ZARA_DB_PROD_DRIVER=postgres
ZARA_DB_PROD_DSN=postgres://user:pass@host:5432/mydb?sslmode=require
ZARA_DB_PROD_MAX_CONNS=10

# MySQL / MariaDB
ZARA_DB_MYSQL_DRIVER=mysql
ZARA_DB_MYSQL_DSN=user:pass@tcp(localhost:3306)/mydb?charset=utf8mb4&parseTime=true

# Alternative: use alias "mariadb" (still uses the mysql driver)
ZARA_DB_SERVICE_DRIVER=mariadb
ZARA_DB_SERVICE_DSN=user:pass@tcp(host:3306)/mydb

# SQL Server
ZARA_DB_MSSQL_DRIVER=sqlserver
ZARA_DB_MSSQL_DSN=sqlserver://user:pass@localhost:1433?database=mydb&encrypt=disable

# SQLite
ZARA_DB_LOCAL_DRIVER=sqlite
ZARA_DB_LOCAL_DSN=/tmp/dev.db

# Auto-detect (no DRIVER needed)
ZARA_DB_AUTO_DSN=postgres://user:pass@localhost:5432/mydb
```

### Supported Drivers

| Driver | Aliases | Dialect Auto-Detect |
|--------|---------|-------------------|
| `postgres` | `pg`, `postgresql` | `postgres://` / `postgresql://` |
| `mysql` | `mariadb`, `maria` | `mysql://` / `mariadb://` / `user@tcp(...)` / `user@unix(...)` |
| `sqlserver` | `mssql`, `microsoft` | `sqlserver://` |
| `sqlite` | `sqlite3` | `sqlite://` / `*.db` / `*.sqlite` / `*.sqlite3` |

How it works: if `ZARA_DB_<NAME>_DRIVER` is unknown or empty, the system auto-detects the driver from the DSN format. Just set `_DSN` and you're good.

When you call `db_query`, results are automatically scanned for sensitive data:

```
Agent: db_query(database="prod", query="SELECT email, api_key FROM users")
  ↓
MCP:  Executes query → scans every cell → masks secrets/PII
  ↓
Agent: Receives results with [API_KEY_1], [EMAIL_1] masked
```

---

## HTTP API Proxy

Configure APIs as safer alternatives to raw curl:

```bash
ZARA_API_GITHUB_URL=https://api.github.com
ZARA_API_GITHUB_AUTH=bearer
ZARA_API_GITHUB_AUTH_ENV=GITHUB_TOKEN
```

Auth tokens are injected from env vars — they never appear in prompts or agent context. Response bodies are scanned for secrets and masked automatically.

---

## AI Provider Proxy

Configure any OpenAI-compatible provider:

```bash
ZARA_AI_OPENAI_BASE_URL=https://api.openai.com
ZARA_AI_OPENAI_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_OPENAI_MODELS=gpt-4o,gpt-4o-mini
```

When you call `ai_chat`, the provider proxy automatically:

1. **Redacts** all messages before sending (secrets → `[PLACEHOLDER]`)
2. **Sends** the safe prompt to the LLM
3. **Unredacts** the response before returning to agent

This means you can safely include sensitive context in your prompts — it never reaches the LLM provider unmasked.

Supported: **OpenAI**, **Anthropic**, **Gemini**, **DeepSeek**, **OpenRouter**, **Groq**, and any OpenAI-compatible API (Ollama, vLLM, LocalAI, etc.)

---

## Configuration

Zara Privacy MCP runs as a **sidecar process** managed by OpenCode. Once configured, OpenCode spawns the binary automatically and communicates over stdio.

### 1. Build and install

```bash
cd zara-privacy-mcp
make install
# Installed to /usr/local/bin/zara-privacy-mcp
```

### 2. Set environment variables

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
# Required for privacy features
export ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-32-chars"

# Optional: Database connections
export ZARA_DB_PROD_DRIVER=postgres
export ZARA_DB_PROD_DSN=postgres://user:pass@localhost:5432/mydb

# Optional: HTTP APIs
export ZARA_API_GITHUB_URL=https://api.github.com
export ZARA_API_GITHUB_AUTH=bearer
export ZARA_API_GITHUB_AUTH_ENV=GITHUB_TOKEN

# Optional: AI Providers
export ZARA_AI_OPENAI_BASE_URL=https://api.openai.com
export ZARA_AI_OPENAI_API_KEY_ENV=OPENAI_API_KEY
export ZARA_AI_OPENAI_MODELS=gpt-4o,gpt-4o-mini
```

### 3. Add to `opencode.json`

The MCP server is already configured in both the project and global `opencode.json`:

```json
{
  "mcp": {
    "zara-privacy-mcp": {
      "type": "local",
      "command": ["zara-privacy-mcp", "--stdio"],
      "enabled": true,
      "environment": {
        "ZARA_ENCRYPTION_KEY": "{env:ZARA_ENCRYPTION_KEY}",
        "ZARA_DB_PATH": "{env:ZARA_DB_PATH:~/.zara/privacymcp/mappings.db}",
        "ZARA_LOG_LEVEL": "{env:ZARA_LOG_LEVEL:info}"
      },
      "timeout": 30000
    }
  }
}
```

### 4. Restart OpenCode

Close and reopen OpenCode, or reload config. OpenCode spawns `zara-privacy-mcp --stdio` on startup. All 15 tools are available to agents automatically.

---

## Testing with Postman

The HTTP server mode is the easiest way to test all 7 tools interactively.

### 1. Start the HTTP server

```bash
export ZARA_ENCRYPTION_KEY="dev-key-32-bytes-long-for-testing!!"
make run-dev
```

### 2. Import the Postman collection

Import `scripts/postman-collection.json` into Postman. It contains 10 pre-built requests.

### 3. JSON-RPC Protocol

All tool calls use the same pattern:

```
POST http://127.0.0.1:8530/mcp
Content-Type: application/json
```

**Initialize the session:**

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize"
}
```

**List available tools:**

```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "list_tools"
}
```

**Call a tool:**

```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "call_tool",
    "params": {
        "name": "scan_context",
        "arguments": {
            "text": "My API key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456"
        }
    }
}
```

### 4. Health check

```
GET http://127.0.0.1:8530/health
```

Returns server status, version, and mapping store statistics.

### 5. Quick curl examples

```bash
# List tools
curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"list_tools"}' | jq

# Scan for secrets
curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"call_tool",
    "params":{"name":"scan_context","arguments":{"text":"My email is test@email.com"}}
  }' | jq

# Redact sensitive data
curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":3,"method":"call_tool",
    "params":{"name":"redact_context","arguments":{"text":"My KTP is 3172051234567890"}}
  }' | jq

# Health check
curl http://127.0.0.1:8530/health | jq
```

### 6. Full workflow (scan → redact → send → unredact)

```bash
# 1. Scan context first
SCAN=$(curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":1,"method":"call_tool",
    "params":{"name":"scan_context",
      "arguments":{"text":"My email is budi@example.com and key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456"}}
  }')
echo "Scan result: $(echo $SCAN | jq '.result.content[0].json.risk_score')"

# 2. Redact before sending to LLM
REDACTED=$(curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"call_tool",
    "params":{"name":"redact_context",
      "arguments":{"text":"My email is budi@example.com and key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456"}}
  }')
SAFE_TEXT=$(echo $REDACTED | jq -r '.result.content[0].json.redacted')
echo "Safe to send: $SAFE_TEXT"

# 3. After LLM responds, unredact
LLM_RESPONSE="Your account [API_KEY_1] has been verified with email [EMAIL_1]."
RESTORED=$(curl -s http://127.0.0.1:8530/mcp \
  -H 'Content-Type: application/json' \
  -d "{
    \"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"call_tool\",
    \"params\":{\"name\":\"unredact_response\",
      \"arguments\":{\"text\":\"$LLM_RESPONSE\"}}
  }")
echo "Restored: $(echo $RESTORED | jq -r '.result.content[0].text')"
```

---

## Configuration

All via environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `ZARA_ENCRYPTION_KEY` | — | AES-256-GCM key (min 16 chars, **REQUIRED**) |
| `ZARA_MCP_TRANSPORT` | `http` | Transport mode: `http` or `stdio` |
| `ZARA_MCP_PORT` | `8530` | MCP server port (HTTP mode) |
| `ZARA_MCP_HOST` | `127.0.0.1` | Bind address (HTTP mode) |
| `ZARA_DB_PATH` | `~/.zara/privacymcp/mappings.db` | SQLite database path |
| `ZARA_LOG_LEVEL` | `info` | Log verbosity |
| `ZARA_MAX_TOKENS` | `4096` | Compression token budget |
| `ZARA_METRICS_ENABLED` | `true` | Enable metrics server |

---

## Secret Detection Coverage

| Category | Examples |
|----------|---------|
| **AI API Keys** | OpenAI (`sk-proj-*`), Anthropic (`sk-ant-*`), Gemini (`AIza*`), DeepSeek |
| **Cloud** | AWS Access Key (`AKIA*`), AWS Secret Key |
| **Auth Tokens** | JWT (`eyJ*.*.*`), Bearer, OAuth, Session cookies |
| **Database** | PostgreSQL, MySQL, MongoDB, Redis connection URLs |
| **Crypto** | SSH keys, RSA/EC/PEM private keys, certificates |
| **Generic** | High-entropy strings (Shannon entropy > 4.0) |
| **PII (Global)** | Email, phone, credit card, IP |
| **PII (Indonesia)** | NIK/KTP, NPWP, passport, SIM, phone |
| **PII (Singapore)** | NRIC, FIN, passport, phone |

---

## Phase Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **1** | Scan + Redact + Unredact (deterministic detection) | ✅ **Completed** |
| **2** | Context compression + memory filter + metrics | ✅ **Completed** |
| **3** | Data classification + leadership module | 🚧 **Scaffolded** |
| **4** | Stdio transport + OpenCode MCP integration + Postman testing | ✅ **Completed** |
| **5** | Database proxy (PostgreSQL, SQLite) + auto masking | ✅ **Completed** |
| **6** | HTTP API proxy (safer curl with auto auth + masking) | ✅ **Completed** |
| **7** | AI provider proxy (auto redact/unredact for any LLM) | ✅ **Completed** |
| **8** | MySQL driver support + query parameters | 🔜 **Planned** |
| **9** | NER/semantic secret detection (beyond regex) | 🔜 **Planned** |
| **10** | Encrypted memory vault + audit logging | 🔜 **Planned** |

---

## License

MIT.
