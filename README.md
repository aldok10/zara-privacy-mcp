# Zara Privacy MCP

**Privacy-first MCP gateway for AI agents.** 19 tools: privacy layer + database proxy (SQL/MongoDB/Redis) + HTTP API proxy + AI provider proxy — all with automatic data masking.

```
Agent → MCP (stdio) → DB/HTTP/AI call → auto-mask → Agent
```

> Every outbound call is automatically scanned and masked. Secrets, PII, credentials — zero leaks to external services.

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
OpenCode / Kiro / Any MCP Client
   │  stdio (JSON-RPC)
   ▼
Zara Privacy MCP
   │
   ├── Privacy Layer (always on)
   │   ├── scan/redact/unredact (21 secret + 15 PII patterns)
   │   ├── context compression (dedup, strip, TF-IDF)
   │   ├── memory filter (block high-risk persistence)
   │   └── data classification (PUBLIC → SECRET)
   │
   ├── Database Proxy
   │   ├── SQL: PostgreSQL, MySQL, SQL Server, SQLite, Oracle, ClickHouse
   │   ├── MongoDB: find, list collections
   │   ├── Redis: exec any command, key listing
   │   ├── Driver auto-detect from DSN
   │   └── All results auto-masked before returning
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

---

## 19 MCP Tools

### Privacy (7)

| Tool | Description |
|------|-------------|
| `scan_context` | Detect secrets + PII. Returns risk score + findings. |
| `redact_context` | Replace sensitive data with reversible `[PLACEHOLDER_N]` tokens. |
| `unredact_response` | Restore original values from LLM response placeholders. |
| `compress_context` | Reduce tokens: dedup lines, strip comments, keyword extraction. |
| `memory_filter` | Block high-risk data from being stored in memory. |
| `classify_data` | Assign sensitivity label (PUBLIC, INTERNAL, CONFIDENTIAL, SECRET). |
| `store_stats` | Get mapping store statistics. |

### SQL Database (3)

| Tool | Description |
|------|-------------|
| `db_query` | Execute SQL. Results auto-scanned and masked. |
| `db_list_tables` | List all tables in a database. |
| `db_describe` | Show column schema (name, type, nullable, key). |

### MongoDB (2)

| Tool | Description |
|------|-------------|
| `mongo_find` | Query documents with filter + limit. Results auto-masked. |
| `mongo_list_collections` | List all collections. |

### Redis (2)

| Tool | Description |
|------|-------------|
| `redis_exec` | Execute any Redis command. Results auto-masked. |
| `redis_keys` | List keys matching a pattern. |

### HTTP API (2)

| Tool | Description |
|------|-------------|
| `http_request` | Make HTTP call with auto auth injection + response masking. |
| `http_list_apis` | List configured API endpoints. |

### AI Provider (2)

| Tool | Description |
|------|-------------|
| `ai_chat` | Chat with LLM. Auto-redacts prompt, auto-unredacts response. |
| `ai_list_providers` | List configured providers + models. |

### Config (1)

| Tool | Description |
|------|-------------|
| `config_list` | Show all active connections without exposing secrets. |

---

## Install

### Prerequisites

- Go 1.21+ (no CGo required — pure Go SQLite)

### Step 1: Build

```bash
git clone https://github.com/aldok10/zara-privacy-mcp.git
cd zara-privacy-mcp
make build
```

### Step 2: Setup .env

```bash
cp .env.example .env
```

Edit `.env` with your connections:

```bash
# Required — encryption key for placeholder mapping (min 16 chars)
ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-32-chars"

# SQL Database (add as many as needed, replace <NAME> with your label)
ZARA_DB_PROD_DRIVER=postgres
ZARA_DB_PROD_DSN=postgres://user:pass@host:5432/mydb?sslmode=disable

ZARA_DB_MYSQL_DRIVER=mysql
ZARA_DB_MYSQL_DSN=user:pass@tcp(host:3306)/mydb?charset=utf8mb4

# MongoDB
ZARA_MONGO_APP_URI=mongodb://user:pass@host:27017
ZARA_MONGO_APP_DATABASE=myapp

# Redis
ZARA_REDIS_CACHE_ADDR=host:6379
ZARA_REDIS_CACHE_PASSWORD=secret
ZARA_REDIS_CACHE_DB=0

# HTTP API (auth token read from env var specified in AUTH_ENV)
ZARA_API_GITHUB_URL=https://api.github.com
ZARA_API_GITHUB_AUTH=bearer
ZARA_API_GITHUB_AUTH_ENV=GITHUB_TOKEN

# AI Provider
ZARA_AI_OPENAI_BASE_URL=https://api.openai.com/v1
ZARA_AI_OPENAI_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_OPENAI_MODELS=gpt-4o,gpt-4o-mini
```

### Step 3: Setup wrapper script

The wrapper ensures env vars are passed to the MCP process. Edit `scripts/mcp-wrapper.sh`:

```bash
#!/bin/sh
export ZARA_ENCRYPTION_KEY="your-key-here"
export ZARA_DB_PROD_DRIVER=postgres
export ZARA_DB_PROD_DSN="postgres://user:pass@host:5432/mydb"
# ... add all your env vars from .env
exec /path/to/zara-privacy-mcp --stdio
```

Make it executable:

```bash
chmod +x scripts/mcp-wrapper.sh
```

### Step 4: Register MCP in OpenCode / Kiro

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

Alternative (if your MCP client passes env to child processes):

```json
{
  "mcp": {
    "zara-privacy-mcp": {
      "type": "local",
      "command": ["/absolute/path/to/zara-privacy-mcp", "--stdio"],
      "enabled": true,
      "env": {
        "ZARA_ENCRYPTION_KEY": "your-key-here",
        "ZARA_DB_PROD_DSN": "postgres://user:pass@host:5432/mydb"
      }
    }
  }
}
```

### Step 5: Restart and verify

Restart OpenCode/Kiro, then verify tools are loaded:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | /path/to/scripts/mcp-wrapper.sh 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d[\"result\"][\"tools\"])} tools loaded')"
```

Expected output: `19 tools loaded`

### Optional: Install binary globally

```bash
sudo make install   # Installs to /usr/local/bin/zara-privacy-mcp
```

### Optional: Install agent skill

```bash
make install-skill  # Copies skill to ~/.agents/skills/ and ~/.claude/skills/
```

---

## Configuration

All via environment variables. See `.env.example` for a template.

### Global (required)

```bash
ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-16-chars"
```

### SQL Database

```bash
# Auto-detect driver from DSN (no _DRIVER needed)
ZARA_DB_<NAME>_DSN=postgres://user:pass@host:5432/db

# Or explicit driver
ZARA_DB_<NAME>_DRIVER=postgres|mysql|sqlserver|sqlite|oracle|clickhouse
ZARA_DB_<NAME>_DSN=<connection_string>
ZARA_DB_<NAME>_MAX_CONNS=10
```

Supported drivers: `postgres` (pg), `mysql` (mariadb), `sqlserver` (mssql), `sqlite` (sqlite3), `oracle` (ora), `clickhouse` (ch).

### MongoDB

```bash
ZARA_MONGO_<NAME>_URI=mongodb://user:pass@host:27017
ZARA_MONGO_<NAME>_DATABASE=mydb
```

### Redis

```bash
ZARA_REDIS_<NAME>_ADDR=host:6379
ZARA_REDIS_<NAME>_USERNAME=optional
ZARA_REDIS_<NAME>_PASSWORD=optional
ZARA_REDIS_<NAME>_DB=0
```

### HTTP API

```bash
ZARA_API_<NAME>_URL=https://api.example.com
ZARA_API_<NAME>_AUTH=bearer|basic|header|none
ZARA_API_<NAME>_AUTH_ENV=TOKEN_ENV_VAR_NAME
```

### AI Provider

```bash
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com/v1
ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini
```

---

## Detection Coverage

### Secrets (21 patterns)

| Category | Examples |
|----------|---------|
| AI API Keys | OpenAI (`sk-proj-*`), Anthropic (`sk-ant-*`), Gemini (`AIza*`), DeepSeek |
| Cloud | AWS Access Key (`AKIA*`), AWS Secret Key |
| Auth Tokens | JWT (`eyJ*.*.*`), Bearer, OAuth, Session cookies |
| Database URLs | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Private Keys | SSH, RSA, EC, PEM, certificates |
| Generic | High-entropy strings (Shannon entropy > 4.0) |

### PII (15 patterns)

| Locale | Patterns |
|--------|----------|
| Global | Email, Phone, Credit Card (Visa/MC/Amex/Discover), IP Address |
| Indonesia | NIK/KTP, NPWP, Passport, Phone (+62), SIM, Postal Code |
| Singapore | NRIC, FIN, Passport, Phone (+65), Postal Code |

---

## Development

```bash
make build          # Build binary
make test           # Run tests with race detection
make test-coverage  # Generate coverage report
make run-dev        # Run with debug logging
make smoke          # Quick stdio smoke test
make lint           # go vet + staticcheck
make clean          # Remove build artifacts
```

### Hot Reload

```bash
kill -HUP $(pgrep zara-privacy-mcp)
```

Re-reads all environment variables and applies new connections without restart.

---

## MCP Protocol

Supports both method formats:
- Legacy: `list_tools`, `call_tool`
- MCP Spec: `tools/list`, `tools/call`

Transport modes:
- **stdio**: Newline-delimited JSON-RPC via stdin/stdout. For MCP client integration.
- **HTTP**: POST to `/mcp`. For development/testing with Postman.

---

## License

MIT.
