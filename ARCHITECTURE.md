# Architecture

## Layered DDD Structure

```
┌─────────────────────────────────────────────────────────┐
│                    cmd/server/main.go                     │
│              Composition Root (wiring only)               │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                     transport/                            │
│  mcp-go server, tool registration, middleware            │
│  (rate limiting, audit logging, panic recovery)          │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                  application/tools/                       │
│  Tool handlers (19 handlers), security validators        │
│  Each handler: parse args → validate → delegate → format │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                       domain/                            │
│  Interfaces, value objects, strategies, policies         │
│  ┌─────────┐ ┌────────────┐ ┌─────────┐ ┌──────┐      │
│  │ privacy │ │ datasource │ │ gateway │ │  ai  │      │
│  │         │ │            │ │         │ │      │      │
│  │-masker  │ │-datasource │ │-proxy   │ │-prov │      │
│  │-engine  │ │-dialect    │ │         │ │-gate │      │
│  │-store   │ │            │ │         │ │-adapt│      │
│  │-strategy│ │            │ │         │ │      │      │
│  └─────────┘ └────────────┘ └─────────┘ └──────┘      │
│                    domain/errors.go                       │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                      internal/                           │
│  Implementations (infrastructure layer)                  │
│  ┌──────────┐ ┌──────┐ ┌────────┐ ┌───────┐ ┌───────┐ │
│  │ detector │ │engine│ │  db    │ │ http  │ │  ai   │ │
│  │(secret)  │ │redact│ │registry│ │client │ │provid.│ │
│  │(pii)     │ │      │ │mongo   │ │       │ │       │ │
│  │          │ │      │ │redis   │ │       │ │       │ │
│  └──────────┘ └──────┘ └────────┘ └───────┘ └───────┘ │
│  ┌────────┐ ┌───────┐ ┌──────────┐ ┌───────────────┐   │
│  │ crypto │ │ store │ │ masking  │ │  lifecycle    │   │
│  │AES-GCM │ │SQLite │ │(shared)  │ │(startup/stop) │   │
│  └────────┘ └───────┘ └──────────┘ └───────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

```
Agent (stdin)
  │ JSON-RPC
  ▼
transport/server.go (mcp-go)
  │ rate limit → audit → dispatch
  ▼
application/tools/handlers.go
  │ parse + validate + security gate
  ▼
internal/* (execute)
  │ query DB / call API / chat AI
  ▼
internal/masking/masker.go
  │ scan + mask secrets/PII
  ▼
Agent (stdout) ← masked result
```

## Design Patterns

| Pattern | Where | Purpose |
|---------|-------|---------|
| Strategy | `domain/privacy/strategy.go` | Pluggable detection algorithms |
| Adapter | `domain/ai/adapter.go` | Provider-specific communication |
| Repository | `domain/privacy/store.go` | Encrypted mapping persistence |
| Gateway | `domain/ai/gateway.go` | Input/output policy enforcement |
| Composite | `domain/privacy/strategy.go` | Chain multiple detectors |
| Middleware | `transport/server.go` | Rate limit, audit, recovery |
| Lifecycle | `internal/lifecycle/app.go` | Ordered start/stop |
| Factory | `domain/datasource/dialect.go` | Driver-specific SQL generation |

## Security Layers

```
Layer 1: Input validation (application/tools/security.go)
    ├── SQL: block DROP/TRUNCATE/ALTER, require WHERE on DELETE/UPDATE
    ├── Redis: block FLUSHALL/SHUTDOWN/EVAL/CONFIG
    └── MongoDB: block $where/$expr/$function

Layer 2: SSRF protection (internal/http/client.go)
    ├── Block private IPs (10.x, 172.16.x, 192.168.x, 127.x)
    ├── Block cloud metadata (169.254.169.254)
    └── Block non-HTTP schemes

Layer 3: Data masking (internal/masking/masker.go)
    ├── 21 secret patterns (API keys, tokens, private keys)
    ├── 15 PII patterns (email, phone, NIK, NRIC, credit card)
    └── Auto-applied to all DB/HTTP/Redis/Mongo results

Layer 4: AI gateway (domain/ai/gateway.go)
    ├── Redact input before sending to provider
    ├── Scan output for leaked PII
    └── Policy-based blocking

Layer 5: Transport hardening (transport/server.go)
    ├── Panic recovery (server.WithRecovery)
    ├── Rate limiting (max 20 concurrent)
    └── Request hooks (audit log)
```

## Key Decisions

- **mcp-go over hand-rolled**: Eliminates 1300 lines of protocol code, adds panic recovery, middleware, session support
- **Synchronous persist**: SQLite writes are fast (<1ms), async goroutines hide errors
- **Shared Masker**: Single implementation eliminates 4x duplication across DB/Mongo/Redis/HTTP
- **Lifecycle manager**: Ensures ordered shutdown (close DB before store)
- **Domain interfaces**: Enable testing without real infrastructure
