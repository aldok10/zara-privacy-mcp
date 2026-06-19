---
name: zara-privacy-mcp
description: Zara Secure MCP — general-purpose secure gateway with 15 tools: privacy layer, database proxy, HTTP API proxy, and AI provider proxy. All with automatic data masking.
---

# Zara Secure MCP Skill

**General-purpose secure gateway for OpenCode.** Privacy layer + database proxy + HTTP API proxy + AI provider proxy — all with automatic data masking.

```
Agent → MCP → DB/HTTP/AI call → masking → agent
```

> Every outbound call through the MCP is automatically masked. API keys, passwords, PII — zero leaks to external services.
> Renamed from `zara-privacy-mcp` → `zara-privacy-mcp`. Binary: `zara-privacy-mcp`.

---

## 15 Tools — When to Use

### Privacy Layer (always ready, no configuration needed)

| Tool | Trigger | Example User Query |
|------|---------|-------------------|
| `scan_context` | User wants to check context safety, find sensitive data | "Check if this chat has API keys or KTP numbers" |
| `redact_context` | User wants to send context but it has sensitive data | "Mask email & API key in this chat" |
| `unredact_response` | Response contains `[EMAIL_1]` placeholders | "Restore placeholders to original values" |
| `compress_context` | Context is too long, needs token savings | "Compress this chat, remove unimportant tokens" |
| `memory_filter` | Validate data before storing to memory | "Check if this memory is safe to store?" |
| `classify_data` | Check sensitivity level (PUBLIC → SECRET) | "Is this data classified as confidential?" |
| `store_stats` | View placeholder mapping statistics | "How many placeholders have been created?" |

### Database (requires env var configuration)
**Supported**: PostgreSQL, MySQL, MariaDB, SQL Server, SQLite.
**Auto-detect**: just set the DSN — the driver is detected automatically from the URL format.

| Tool | Trigger | Example User Query |
|------|---------|-------------------|
| `db_query` | Execute SQL | "Show users from production database", "Find email for id 5" |
| `db_list_tables` | List database tables | "What tables are in the production database?" |
| `db_describe` | Describe table schema | "Describe the users table schema" |

### HTTP API (requires env var configuration)

| Tool | Trigger | Example User Query |
|------|---------|-------------------|
| `http_request` | Call REST API (secure curl alternative) | "GET /repos from GitHub API", "Create a new issue" |
| `http_list_apis` | List registered APIs | "What APIs are available?" |

### AI Provider (requires env var configuration)

| Tool | Trigger | Example User Query |
|------|---------|-------------------|
| `ai_chat` | Send prompt to external LLM (OpenAI, Anthropic, etc.) via MCP | "Ask GPT-4o about this code", "Ask Claude to refactor this function" |
| `ai_list_providers` | List registered AI providers | "What AI providers are configured?" |

### Config

| Tool | Trigger | Example User Query |
|------|---------|-------------------|
| `config_list` | List all registered connections | "What connections are active?" |

---

## Data Flow & Security Model

### Privacy Layer Flow
```
User: "My key is sk-proj-ABCDefghijklmnopqrstuvwxyz123456"
  → scan_context: risk=4 (CRITICAL), secrets: [OpenAI API Key]
  → redact_context: "My key is [API_KEY_1]"
  → LLM responds → unredact_response restores original values
```

### Database Proxy Flow
```
Agent → db_query("prod", "SELECT email, api_key FROM users")
  → MCP executes query → scans every cell → masks secrets/PII
  → Agent gets: {rows: [{email: "[EMAIL_1]", api_key: "[API_KEY_1]"}], masked: [...]}
```

### HTTP API Proxy Flow
```
Agent → http_request("github", "GET", "/repos/aldok10/zara-privacy-mcp")
  → MCP injects auth header from env → sends request → masks response
  → Agent gets: {status_code: 200, body: "{...}", masked: [...]}
```

### AI Provider Proxy Flow
```
Agent → ai_chat("openai", "gpt-4o", [{role:"user", content:"My key is sk-..."}])
  → MCP redacts messages → sends safe prompt → OpenAI responds
  → MCP unredacts response → Agent gets clean result
```

> **Golden rule**: All masking is transparent. Agent and user don't need to think about it.

---

## Configuration (Environment Variables)

Database, HTTP API, and AI tools require env vars. Uses prefix-based naming — just add your own name.

### Database
**Supported drivers**: `postgres`, `mysql`, `mariadb`, `sqlserver`, `sqlite`
**Aliases**: pg / postgresql (postgres), maria (mysql), mssql / microsoft (sqlserver), sqlite3 (sqlite)
**Auto-detect**: if the driver is unknown or empty, the system detects it from the DSN format

```bash
# PostgreSQL
ZARA_DB_PROD_DRIVER=postgres
ZARA_DB_PROD_DSN=postgres://user:pass@host:5432/db?sslmode=require
ZARA_DB_PROD_MAX_CONNS=10

# MySQL / MariaDB
ZARA_DB_MYSQL_DRIVER=mysql
ZARA_DB_MYSQL_DSN=user:pass@tcp(localhost:3306)/db?charset=utf8mb4

# SQL Server
ZARA_DB_MSSQL_DRIVER=sqlserver
ZARA_DB_MSSQL_DSN=sqlserver://user:pass@localhost:1433?database=db

# SQLite
ZARA_DB_LOCAL_DRIVER=sqlite
ZARA_DB_LOCAL_DSN=/tmp/dev.db

# Auto-detect: no need to set DRIVER
ZARA_DB_AUTO_DSN=postgres://user:pass@localhost:5432/db  # → auto-detected as postgres
```

### HTTP API
```bash
ZARA_API_<NAME>_URL=https://api.github.com
ZARA_API_<NAME>_AUTH=bearer|basic|header|none
ZARA_API_<NAME>_AUTH_ENV=GITHUB_TOKEN
```

### AI Provider
```bash
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com/v1
ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini
```

### Global
```bash
ZARA_ENCRYPTION_KEY="your-32-char-key-here-minimum!!"
ZARA_DB_PATH=/path/to/mapping.db
ZARA_LOG_LEVEL=debug|info|warn|error
```

---

## Example Scenarios

### 1. "Fetch user data from database"
User: "Get user with email budi@example.com from production database"
```
Agent → db_query(database="prod", query="SELECT * FROM users WHERE email=$1", params=["budi@example.com"])
  → Results auto-masked if sensitive data is found
  → Display to user with masking info
```

### 2. "Create a GitHub issue"
User: "Create a new issue titled 'Add MySQL support'"
```
Agent → http_request(api="github", method="POST", path="/repos/aldok10/zara-privacy-mcp/issues", body={title:"Add MySQL support"})
  → MCP auto-injects token from env
  → Display results
```

### 3. "Ask an AI about an API key"
User: "Ask GPT-4o whether API key sk-proj-xxx is safe to use?"
```
Agent → ai_chat(provider="openai", model="gpt-4o", messages=[{role:"user", content:"Is the API key sk-proj-xxx safe to use?"}])
  → MCP redacts API key before sending → OpenAI never sees the original
  → Response is unredacted → user sees complete result
```

### 4. "Clean sensitive data"
User: "There are KTP numbers and API keys in this chat, please clean them before I send it"
```
Agent → scan_context(text=...) → identify all sensitive data
  → redact_context(text=...) → masking
  → Display safe text to user
```

---

## Install Skill

There are 2 ways:

### Method 1: Via Makefile (automatic)
```bash
cd /path/to/zara-privacy-mcp
make install-skill
```
This copies the skill to:
- `~/.agents/skills/zara-privacy-mcp/`
- `~/.claude/skills/zara-privacy-mcp/`
- `.opencode/skills/zara-privacy-mcp/` (project)

### Method 2: Manual
```bash
# Copy to global agent directory
cp -r .opencode/skills/zara-privacy-mcp ~/.agents/skills/

# Copy to Claude skills
cp -r .opencode/skills/zara-privacy-mcp ~/.claude/skills/
```

---

## Important Notes

- **Database/API/AI tools need configuration** — if you get an "unknown database" error, guide the user to set the environment variables
- **Privacy tools are always ready** — as long as `ZARA_ENCRYPTION_KEY` is set
- **Masking is automatic** — the agent does not need to explicitly request masking
- **Credentials never appear in prompts** — all auth comes from env vars, injected by the MCP
- **Fallback**: if the MCP does not respond, fall back to manual methods
- **Testing**: `zara-privacy-mcp` (HTTP) or `zara-privacy-mcp --stdio` (sidecar)
