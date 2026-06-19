---
name: zara-privacy-mcp
description: Zara Privacy MCP skill — 19 tools for privacy scanning, database proxy (SQL/MongoDB/Redis), HTTP API proxy, and AI provider proxy. All with automatic data masking.
---

# Zara Privacy MCP

Privacy-first MCP gateway with 19 tools. All outbound calls through MCP are automatically scanned and masked — secrets, PII, credentials never leak.

```
Agent → MCP → DB/HTTP/AI call → auto-mask → Agent
```

---

## 19 Tools

### Privacy (7 tools, always available)

| Tool | When to Use |
|------|-------------|
| `scan_context` | Check text for secrets/PII. Returns risk score + findings without modifying. |
| `redact_context` | Replace secrets/PII with `[PLACEHOLDER_N]` tokens. Safe to send to LLM. |
| `unredact_response` | Restore original values from placeholders in LLM response. |
| `compress_context` | Reduce tokens: dedup lines, strip comments, extract by keywords. |
| `memory_filter` | Block high-risk data from being stored in memory. |
| `classify_data` | Assign sensitivity: PUBLIC, INTERNAL, CONFIDENTIAL, SECRET. |
| `store_stats` | Show placeholder mapping store statistics. |

### SQL Database (3 tools)

Supported: PostgreSQL, MySQL/MariaDB, SQL Server, SQLite, Oracle, ClickHouse.
Driver auto-detected from DSN — no need to set `_DRIVER`.

| Tool | When to Use |
|------|-------------|
| `db_query` | Execute SQL. Results auto-masked. Params: `database`, `query`, `params[]`. |
| `db_list_tables` | List all tables in a database. |
| `db_describe` | Show column schema (name, type, nullable, key). |

### MongoDB (2 tools)

| Tool | When to Use |
|------|-------------|
| `mongo_find` | Query documents with filter + limit. Results auto-masked. |
| `mongo_list_collections` | List all collections in a database. |

### Redis (2 tools)

| Tool | When to Use |
|------|-------------|
| `redis_exec` | Execute any Redis command (GET, SET, HGETALL, LPUSH, etc). Results auto-masked. |
| `redis_keys` | List keys matching a pattern. |

### HTTP API (2 tools)

| Tool | When to Use |
|------|-------------|
| `http_request` | Make HTTP call with auto-injected auth. Response auto-masked. Params: `api`, `path`, `method`, `headers`, `body`, `timeout`. |
| `http_list_apis` | List configured API endpoints. |

### AI Provider (2 tools)

Supports: OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, Groq, any OpenAI-compatible.

| Tool | When to Use |
|------|-------------|
| `ai_chat` | Send prompt to LLM. Auto-redacts before send, auto-unredacts response. |
| `ai_list_providers` | List configured providers + models. |

### Config (1 tool)

| Tool | When to Use |
|------|-------------|
| `config_list` | Show all active connections (databases, APIs, AI providers) without exposing secrets. |

---

## Detection Capabilities

### Secrets (21 patterns)

- AI keys: OpenAI (`sk-proj-*`, legacy), Anthropic (`sk-ant-*`), Gemini (`AIza*`), DeepSeek
- Cloud: AWS Access Key (`AKIA*`), AWS Secret Key
- Tokens: JWT (`eyJ*`), Bearer, OAuth/session tokens
- Private keys: SSH, RSA, EC, PEM
- Database URLs: PostgreSQL, MySQL, MongoDB, Redis connection strings
- URLs with embedded credentials
- High-entropy generic strings (Shannon entropy > 4.0)

### PII (15 patterns)

- **Global**: Email, Phone, Credit Card (Visa/MC/Amex/Discover), IP Address
- **Indonesia**: NIK/KTP, NPWP, Passport, Phone (+62), SIM, Postal Code
- **Singapore**: NRIC, FIN, Phone (+65), Passport, Postal Code

---

## Database Query Rules

When using `db_query`, always follow these to avoid killing production databases.

### Mandatory

1. **Always LIMIT** — default 50, never unbounded SELECT
2. **Always WHERE** — no full table scans
3. **Parameterized queries** — use `?` or `$1`, never string concat
4. **COUNT first if unsure** — estimate size before fetching rows
5. **Specific columns** on large tables — no `SELECT *` unless single row

### Index Awareness

Filter on indexed columns first:
- Primary keys: `id`, `Login`, `Deal`, `Order`
- Foreign keys: `Login` on deals/orders/positions
- Timestamps: `Time`, `Registration`, `LastAccess`
- Unique: `Email`, `ExternalID`

```sql
-- Good: indexed columns in WHERE
SELECT * FROM mt5_deals WHERE Login = ? AND Time >= ? LIMIT 50

-- Bad: full scan on non-indexed column
SELECT * FROM mt5_deals WHERE Comment LIKE '%text%'
```

### Optimization Patterns

| Need | Do | Don't |
|------|-----|-------|
| Time filter | `WHERE Time >= ? AND Time < ?` | `WHERE DATE(Time) = '...'` (kills index) |
| Aggregate | `GROUP BY Login` + `LIMIT` | `SELECT *` + `GROUP BY` |
| Existence | `SELECT 1 ... LIMIT 1` | `SELECT COUNT(*) FROM full_table` |
| Join | On indexed FK only | Cross-join or non-indexed join |
| Sort | `ORDER BY indexed_col LIMIT n` | `ORDER BY` without LIMIT |

### Anti-patterns (never do)

- `SELECT *` on 100k+ rows without WHERE
- `LIKE '%x%'` full scan
- Functions on indexed cols: `WHERE YEAR(Time) = 2026`
- Subqueries that scan full tables
- `DISTINCT` on non-indexed columns
- Multiple JOINs without proper WHERE

### Workflow

1. Identify table + filter columns
2. If unsure: `SELECT COUNT(*) FROM t WHERE <filter>` first
3. If count > 1000: narrow filter or increase LIMIT awareness
4. Aggregate first (COUNT/SUM/GROUP BY), detail later
5. Results come back auto-masked — display directly

### CTE (When Needed)

Use CTE for:
- Multi-step aggregation (filter → aggregate → join details)
- Period comparison (this week vs last week)
- Reusing same subquery result multiple times
- Running totals / window functions

Don't use CTE when plain WHERE + GROUP BY is enough.

```sql
-- Multi-step: top depositors + user details
WITH deposits AS (
  SELECT Login, COUNT(*) as cnt, SUM(Profit) as total
  FROM mt5_deals
  WHERE Action = 2 AND Profit > 0
    AND Time >= '2026-06-01' AND Time < '2026-06-02'
  GROUP BY Login
  HAVING total > 1000
)
SELECT d.*, u.Name, u.Group
FROM deposits d
JOIN mt5_users u ON d.Login = u.Login
ORDER BY d.total DESC LIMIT 20
```

```sql
-- Period comparison
WITH this_week AS (
  SELECT Login, SUM(Profit) as total
  FROM mt5_deals
  WHERE Action = 2 AND Profit > 0
    AND Time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
  GROUP BY Login
),
last_week AS (
  SELECT Login, SUM(Profit) as total
  FROM mt5_deals
  WHERE Action = 2 AND Profit > 0
    AND Time >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
    AND Time < DATE_SUB(CURDATE(), INTERVAL 7 DAY)
  GROUP BY Login
)
SELECT COALESCE(tw.Login, lw.Login) as Login,
       COALESCE(tw.total, 0) as this_week,
       COALESCE(lw.total, 0) as last_week
FROM this_week tw
LEFT JOIN last_week lw ON tw.Login = lw.Login
ORDER BY this_week DESC LIMIT 30
```

```sql
-- Running balance
WITH ordered AS (
  SELECT Deal, Profit, Time,
         SUM(Profit) OVER (ORDER BY Time) as running_balance
  FROM mt5_deals
  WHERE Login = ? AND Action = 2
)
SELECT * FROM ordered LIMIT 50
```

CTE rules:
- Always LIMIT final SELECT
- Filter early inside CTE (WHERE on indexed cols)
- Keep CTEs small — never scan full tables inside
- Name CTEs descriptively

---

## Configuration

All via environment variables with prefix-based naming.

```bash
# SQL Database
ZARA_DB_<NAME>_DRIVER=postgres|mysql|sqlserver|sqlite|oracle|clickhouse
ZARA_DB_<NAME>_DSN=<connection_string>
ZARA_DB_<NAME>_MAX_CONNS=10

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

# Global
ZARA_ENCRYPTION_KEY=<min-16-chars>
ZARA_DB_PATH=~/.zara/privacymcp/mappings.db
```

---

## Important Behavior

- **All masking is automatic** — agent does not need to explicitly mask
- **Credentials never appear in prompts** — auth injected from env vars by MCP
- **Privacy tools always ready** — only need `ZARA_ENCRYPTION_KEY`
- **DB/API/AI tools need env vars** — if "unknown database" error, check configuration
- **Hot reload**: `kill -HUP` to reload config without restart
- **Transport**: `--stdio` for MCP client, HTTP for standalone/testing
