# Zara Privacy MCP — Agent Instructions

Context security layer for OpenCode. Detects, redacts, and restores secrets and PII so sensitive data never reaches LLM providers unredacted.

## Architecture

- Sidecar Go process alongside OpenCode, communicates via JSON-RPC (MCP protocol)
- Single direct dependency: `modernc.org/sqlite` (pure Go, no CGo)
- AES-256-GCM encrypted mapping table for reversible placeholders

## Project Structure

```
cmd/server/main.go           — Entry point, wires config + detectors + store + MCP
├── config/config.go         — Env-based configuration
├── internal/
│   ├── detector/
│   │   ├── types.go         — Core types (Finding, Risk, Classification, Mapping)
│   │   ├── secret.go        — ~20 regex patterns: API keys, tokens, credentials
│   │   ├── pii.go           — ~15 patterns: email, KTP, NPWP, NRIC, credit cards
│   ├── crypto/cipher.go     — AES-256-GCM encrypt/decrypt
│   ├── store/mapping.go     — SQLite-backed placeholder store with encrypted values
│   ├── engine/redact.go     — Scan → Redact → Unredact orchestration
│   ├── compress/compressor.go — Dedup, comment removal, TF-IDF extraction
│   ├── classify/classifier.go — Sensitivity classification (PUBLIC → SECRET)
│   ├── metrics/metrics.go   — Prometheus-compatible counters
│   └── mcp/server.go        — 7 MCP tools + JSON-RPC handler
├── .env.example             — All configuration variables
├── go.mod / go.sum          — Module definition
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_context` | Detect secrets + PII, return risk score and findings |
| `redact_context` | Replace sensitive data with reversible `[PLACEHOLDER_N]` tokens |
| `unredact_response` | Restore original values from LLM responses |
| `compress_context` | Deduplicate, remove comments, extract relevant sections |
| `memory_filter` | Block high-risk data from persisting to memory |
| `classify_data` | Assign sensitivity label based on content + scan results |
| `store_stats` | Mapping store statistics |

## Code Standards

- Go 1.21+ standard layout (`cmd/`, `internal/`, `config/`)
- No CGo — pure Go SQLite driver
- `go vet` clean at all times
- Tests for every detection engine + integration pipeline
- Functional options or explicit constructors, never global state

## Coverage

- **Secrets**: OpenAI, Anthropic, Gemini, DeepSeek, AWS, JWT, Bearer, SSH/PEM, Database URLs, OAuth, session cookies
- **PII**: Email, phone (global/ID/SG), credit card, KTP/NIK, NPWP, NRIC/FIN, passports, IP (filters private ranges)
- **Locales**: `id` (Indonesia), `sg` (Singapore), `global` (everything)
- **Fallback**: High-entropy string detection (Shannon entropy > 4.0)

## Important

- Encryption key must be set via `ZARA_ENCRYPTION_KEY` env var (min 16 chars)
- Mappings are encrypted at rest with AES-256-GCM — only the `crypto` package handles keys
- Detection is deterministic (regex + entropy) in Phase 1; NER/semantic comes in Phase 4
- The server is stateless between requests except for the mapping store
- Default binding is `127.0.0.1` — only localhost can connect
