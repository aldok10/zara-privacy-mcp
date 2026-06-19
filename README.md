# Zara Privacy MCP

**Context security layer for OpenCode.** A sidecar MCP server that sits between OpenCode and any LLM provider — automatically detecting, redacting, and restoring sensitive data so secrets and PII never leave your machine unredacted.

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
    │
    │  JSON-RPC (MCP Protocol)
    ▼
Zara Privacy MCP (Sidecar)
    │
    ├── engine/redact.go    — Scan → Redact → Unredact pipeline
    ├── detector/secret.go   — API keys, tokens, credentials
    ├── detector/pii.go      — Email, KTP, NPWP, NRIC, credit cards
    ├── crypto/cipher.go     — AES-256-GCM encryption
    ├── store/mapping.go     — Encrypted SQLite mapping table
    ├── compress/compressor.go — Context dedup & extraction
    ├── classify/classifier.go — Sensitivity classification
    └── mcp/server.go        — 7 MCP tools
    │
    ▼
LLM Provider (OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, etc.)
```

---

## Tools

| Tool | What It Does |
|------|-------------|
| `scan_context` | Detect secrets + PII. Returns risk score + findings. No modification. |
| `redact_context` | Replace sensitive data with `[PLACEHOLDER_N]` tokens. |
| `unredact_response` | Restore original values from LLM responses. |
| `compress_context` | Dedup, remove comments, extract key sections. Save tokens. |
| `memory_filter` | Validate memory before persistence. Block high-risk data. |
| `classify_data` | Assign sensitivity label (PUBLIC → SECRET). |
| `store_stats` | Get mapping store statistics. |

---

## Quick Start

### Prerequisites

- Go 1.21+
- No CGo required (pure Go SQLite via `modernc.org/sqlite`)

### Run

```bash
git clone https://github.com/aldok10/zara-privacy-mcp.git
cd zara-privacy-mcp

export ZARA_ENCRYPTION_KEY="your-strong-passphrase-min-16-chars"
go run ./cmd/server/
```

Server starts on `127.0.0.1:8530/mcp`.

### Test

```bash
go test -v -count=1 ./...
```

---

## Configuration

All via environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `ZARA_ENCRYPTION_KEY` | — | AES-256-GCM key (min 16 chars, **REQUIRED**) |
| `ZARA_MCP_PORT` | `8530` | MCP server port |
| `ZARA_MCP_HOST` | `127.0.0.1` | Bind address |
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
| **1** | Scan + Redact + Unredact (deterministic detection) | ✅ **Done** |
| **2** | Context compression + memory filter + metrics | ✅ **Done** |
| **3** | Data classification + leadership module | 🚧 **Scaffolded** |
| **4** | NER/semantic detection, OpenCode hooks | 🔜 |
| **5** | Encrypted memory vault, audit logging | 🔜 |

---

## License

MIT.
