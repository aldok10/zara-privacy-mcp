# Zara Secure MCP — Agent Instructions

**General-purpose secure MCP gateway.** Privacy layer + database proxy + HTTP API proxy + AI provider proxy — all with automatic data masking.

Data flow: `Agent → MCP → DB/HTTP/AI call → masking → agent`

## Architecture

```
OpenCode
   │  MCP (stdio)
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
    │   ├── Auto-mask results before returning
    │   └── Schema discovery (list tables, describe)
   ├── HTTP API Proxy
   │   ├── Configurable endpoints with auth
   │   ├── Auto-mask responses
   │   └── Safer alternative to raw curl
   │
   └── AI Provider Proxy
       ├── OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter
       ├── Auto-redact before sending
       ├── Auto-unredact after response
       └── Provider-agnostic
```

## Project Structure

```
cmd/server/main.go           — Entry point, wires everything
config/config.go             — Core + DB + HTTP + AI provider config from env
internal/
├── detector/                — Secret + PII detection (existing)
│   ├── types.go, secret.go, pii.go
├── engine/                  — Redact/unredact pipeline (existing)
├── crypto/                  — AES-256-GCM encryption (existing)
├── store/                   — Encrypted mapping store (existing)
├── compress/                — Context compression (existing)
├── classify/                — Sensitivity classification (existing)
├── metrics/                 — Prometheus counters (existing)
├── db/                      — Database proxy (NEW)
│   └── registry.go          — Connection pool, query with masking
├── http/                    — HTTP API proxy (NEW)
│   └── client.go            — Request/response with masking
├── ai/                      — AI provider proxy (NEW)
│   └── provider.go          — Chat with auto redact/unredact
└── mcp/server.go            — MCP server with 15 tools
```

## 15 MCP Tools

### Privacy (7)
| Tool | Description |
|------|-------------|
| `scan_context` | Detect secrets + PII, return risk score |
| `redact_context` | Replace sensitive data with `[PLACEHOLDER]` |
| `unredact_response` | Restore original values from LLM response |
| `compress_context` | Dedup, remove comments, extract key sections |
| `memory_filter` | Block high-risk data from memory |
| `classify_data` | Assign sensitivity label |
| `store_stats` | Mapping store statistics |

### Database (3)
| Tool | Description |
|------|-------------|
| `db_query` | Execute SQL, results auto-masked |
| `db_list_tables` | List all tables |
| `db_describe` | Show column schema |

### HTTP API (2)
| Tool | Description |
|------|-------------|
| `http_request` | Make API call, auto-mask response |
| `http_list_apis` | List configured endpoints |

### AI Provider (2)
| Tool | Description |
|------|-------------|
| `ai_chat` | Chat with LLM, auto redact/unredact |
| `ai_list_providers` | List configured providers + models |

### Config (1)
| Tool | Description |
|------|-------------|
| `config_list` | Show all configured connections |

## Configuration (via env vars)

### Database
Supported drivers: `postgres`, `mysql`, `mariadb`, `sqlserver`, `sqlite`
Auto-detect: if the driver is unknown, it is detected from the DSN format

```
ZARA_DB_<NAME>_DRIVER=postgres|mysql|mariadb|sqlserver|sqlite
ZARA_DB_<NAME>_DSN=postgres://user:pass@host:5432/db
ZARA_DB_<NAME>_MAX_CONNS=10
```

### HTTP API
```
ZARA_API_<NAME>_URL=https://api.example.com
ZARA_API_<NAME>_AUTH=bearer|basic|header|none
ZARA_API_<NAME>_AUTH_ENV=GITHUB_TOKEN
```

### AI Provider
```
ZARA_AI_<NAME>_BASE_URL=https://api.openai.com
ZARA_AI_<NAME>_API_KEY_ENV=OPENAI_API_KEY
ZARA_AI_<NAME>_MODELS=gpt-4o,gpt-4o-mini
```

## Important

- All outbound data passes through the privacy engine automatically
- DB query results are masked before returning to agent
- HTTP API responses are scanned for secrets/PII
- AI chat messages are redacted before sending, unredacted after
- Encryption key must be set via `ZARA_ENCRYPTION_KEY` env var
- Default binding is `127.0.0.1` — localhost only
