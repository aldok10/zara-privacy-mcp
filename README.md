# Zara Privacy MCP

**Privacy-first MCP gateway for AI agents.** 20 tools: privacy layer + database proxy (SQL/MongoDB/Redis) + HTTP API proxy + AI provider proxy — all with automatic data masking.

```
Agent → MCP (stdio) → DB/HTTP/AI call → auto-mask → Agent
```

---

## Architecture

```
cmd/server/main.go              — Entry point (runfx/fx DI lifecycle)
internal/bootstrap/             — Dependency wiring (fx.Module)
transport/server.go             — mcp-go server, 20 tools, middleware
application/tools/              — Tool handlers + security validators
domain/                         — Interfaces, strategies, errors (DDD)
internal/
├── ai/                         — AI provider proxy + router + fallback + quota + format translation
├── db/                         — SQL + MongoDB + Redis proxy with auto-masking
├── http/                       — HTTP API proxy with SSRF protection + retry (3 attempts)
├── detector/                   — Secret (24 patterns) + PII (18 patterns) detection
├── engine/                     — Redact/unredact pipeline
├── masking/                    — Shared mask helper
├── store/                      — Encrypted SQLite mapping store (AES-256-GCM)
├── crypto/                     — AES-256-GCM encryption
├── observe/                    — OpenObserve telemetry
├── audit/                      — File-based audit logging
└── version/                    — Build-time version injection
config/                         — Env config + validation + SIGHUP reload
```

**Stats:** 54 Go files, 9 test suites, 20 tools, 24 secret patterns, 18 PII patterns.

---

## 20 MCP Tools

| Category | Tools |
|----------|-------|
| Privacy (7) | `scan_context`, `redact_context`, `unredact_response`, `compress_context`, `memory_filter`, `classify_data`, `store_stats` |
| SQL Database (3) | `db_query`, `db_list_tables`, `db_describe` |
| MongoDB (2) | `mongo_find`, `mongo_list_collections` |
| Redis (2) | `redis_exec`, `redis_keys` |
| HTTP API (2) | `http_request`, `http_list_apis` |
| AI Provider (3) | `ai_chat`, `ai_list_providers`, `ai_quota_status` |
| Config (1) | `config_list` |

---

## Install

### Step 1: Build

```bash
make build
```

### Step 2: Configure

```bash
cp .env.example .env
# Edit .env with your connections
```

### Step 3: Setup wrapper

```bash
# Edit scripts/mcp-wrapper.sh with your env vars
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

### Step 5: Verify

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | ./scripts/mcp-wrapper.sh 2>/dev/null \
  | python3 -c "import sys,json; print(f'{len(json.load(sys.stdin)[\"result\"][\"tools\"])} tools')"
# Expected: 20 tools
```

---

## Configuration

All via environment variables (see `.env.example`):

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

# AI Provider (comma-separated keys = pool round-robin)
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

---

## Key Features

| Feature | Description |
|---------|-------------|
| Auto-fallback AI routing | Primary → cheap → free (9 providers pre-registered) |
| Multi-account pool | Comma-separated API keys round-robin automatically |
| RTK token compression | tool_result messages compressed before AI calls (20-40% savings) |
| Quota tracking | Per-provider token limits with configurable reset periods |
| Format translation | OpenAI ↔ Anthropic ↔ Gemini native message formats |
| SSRF protection | Blocks private IPs, cloud metadata endpoints |
| Security gates | Blocks DROP/TRUNCATE, FLUSHALL, $where, DELETE without WHERE |
| HTTP retry | Exponential backoff (3 attempts, 100ms/200ms) for 5xx errors |
| Config hot-reload | `kill -HUP $(pgrep zara-privacy-mcp)` re-reads env vars |
| Audit logging | Blocked operations written to file |
| Version tagging | Git tag + commit hash in MCP initialize response |

---

## Detection Coverage

### Secrets (24 patterns)

| Category | Examples |
|----------|---------|
| AI API Keys | OpenAI (`sk-proj-*`), Anthropic (`sk-ant-*`), Gemini (`AIza*`), DeepSeek |
| Cloud | AWS Access Key (`AKIA*`), AWS Secret Key |
| Auth Tokens | JWT (`eyJ*.*.*`), Bearer, OAuth, Session cookies |
| Database URLs | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Private Keys | SSH, RSA, EC, PEM, certificates |
| Generic | High-entropy strings (Shannon entropy > 4.0) |

### PII (18 patterns)

| Locale | Patterns |
|--------|----------|
| Global | Email, Phone, Credit Card, IP Address, US SSN, IBAN |
| Indonesia | NIK/KTP, NPWP, Passport, Phone (+62), SIM, Postal Code |
| Singapore | NRIC, FIN, Phone (+65), Passport, Postal Code |
| Brazil | CPF |

---

## Security (OWASP AISVS Compliant)

Implements controls from OWASP AISVS 1.0 chapters C9 (Agentic Security), C10 (MCP Security), C12 (Monitoring):

- Rate limiting (20 concurrent tool calls max)
- Input size limits (1MB text, 10MB HTTP body)
- SQL injection prevention (parameterized queries, blocked DDL)
- MongoDB operator injection ($where, $expr, $function blocked)
- Redis dangerous commands (FLUSHALL, EVAL, CONFIG, SHUTDOWN blocked)
- SSRF prevention (private IPs, cloud metadata blocked)
- Prompt injection defense (tool output = untrusted data)
- Context timeouts (30s on all DB/HTTP/AI operations)
- Panic recovery via mcp-go middleware
- Audit logging of all blocked operations

---

## Development

```bash
make build          # Build with version injection
make test           # Run tests with race detection
make test-coverage  # Generate coverage report
make lint           # go vet + staticcheck
make smoke          # Quick stdio smoke test
make build-linux    # Cross-compile linux/amd64
make build-darwin   # Cross-compile darwin/arm64
make clean          # Remove build artifacts
```

## Tech Stack

- **Go 1.26** — stdlib-first, no CGo
- **[mark3labs/mcp-go](https://github.com/mark3labs/mcp-go)** — MCP protocol, declarative tool registration, middleware, panic recovery
- **[minifx/runfx](https://gitlab.com/minifx/runfx)** + **[uber-go/fx](https://github.com/uber-go/fx)** — Application lifecycle + dependency injection
- **modernc.org/sqlite** — Pure Go SQLite for encrypted mapping store
- **Semantic versioning** — go-semantic-release in GitHub Actions CI/CD

---

## Support

If this project helps you, consider buying me a coffee:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square)](https://sociabuzz.com/aldok10)

## License

MIT.
