.PHONY: build run test clean install uninstall lint

BINARY   = zara-privacy-mcp
BINDIR   = /usr/local/bin
GO       = go

# Version info injected at build time
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
MODULE      := github.com/aldok10/zara-privacy-mcp
LDFLAGS     := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(BUILD_DATE)
GOFLAGS     = -ldflags="$(LDFLAGS)"

# Detect OS for install path
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    BINDIR = /usr/local/bin
else
    BINDIR = /usr/local/bin
endif

# ─── Build ────────────────────────────────────────────────────────────────────

build:
	@echo "Building $(VERSION) ($(COMMIT)) at $(BUILD_DATE)"
	$(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/server/

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY)-linux-amd64 ./cmd/server/

build-darwin:
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINARY)-darwin-arm64 ./cmd/server/

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY)-windows-amd64.exe ./cmd/server/

# ─── Run ──────────────────────────────────────────────────────────────────────

run: build
	./$(BINARY)

run-stdio: build
	./$(BINARY) --stdio

run-dev:
	ZARA_ENCRYPTION_KEY="dev-key-32-bytes-long-for-testing!!" \
	ZARA_LOG_LEVEL=debug \
	ZARA_DB_PATH=/tmp/zara-privacy-dev.db \
	$(GO) run ./cmd/server/

# ─── Test ─────────────────────────────────────────────────────────────────────

test:
	$(GO) test -v -count=1 -race ./...

test-short:
	$(GO) test -count=1 -short ./...

test-coverage:
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# ─── Lint ─────────────────────────────────────────────────────────────────────

lint:
	$(GO) vet ./...
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

# ─── Install / Uninstall ─────────────────────────────────────────────────────

install: build
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/$(BINARY)
	@echo "Installed $(BINARY) to $(BINDIR)/$(BINARY)"
	@echo ""
	@echo "  Run HTTP mode:  $(BINARY)"
	@echo "  Run stdio mode: $(BINARY) --stdio"
	@echo "  Set env:        export ZARA_ENCRYPTION_KEY=\"your-passphrase\""

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	@echo "Removed $(BINDIR)/$(BINARY)"

# ─── Skill Install / Uninstall ──────────────────────────────────────────────

SKILL_SRC   = .opencode/skills/zara-privacy-mcp
SKILL_NAME  = zara-privacy-mcp
AGENTS_DIR  = $(HOME)/.agents/skills
CLAUDE_DIR  = $(HOME)/.claude/skills

install-skill:
	@echo "Installing skill '$(SKILL_NAME)'..."
	install -d $(AGENTS_DIR)/$(SKILL_NAME)
	install -m 644 $(SKILL_SRC)/SKILL.md $(AGENTS_DIR)/$(SKILL_NAME)/SKILL.md
	@echo "  ✓ $(AGENTS_DIR)/$(SKILL_NAME)/SKILL.md"
	install -d $(CLAUDE_DIR)/$(SKILL_NAME)
	install -m 644 $(SKILL_SRC)/SKILL.md $(CLAUDE_DIR)/$(SKILL_NAME)/SKILL.md
	@echo "  ✓ $(CLAUDE_DIR)/$(SKILL_NAME)/SKILL.md"
	@echo "Installed skill '$(SKILL_NAME)' for all agents"
	@echo ""
	@echo "  Agent can load via: skill(\"$(SKILL_NAME)\")"
	@echo "  Uninstall via:      make uninstall-skill"

uninstall-skill:
	rm -rf $(AGENTS_DIR)/$(SKILL_NAME)
	rm -rf $(CLAUDE_DIR)/$(SKILL_NAME)
	@echo "Removed skill '$(SKILL_NAME)' from all agent directories"

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY)
	rm -f $(BINARY)-linux-amd64
	rm -f $(BINARY)-darwin-arm64
	rm -f coverage.out coverage.html
	rm -rf /tmp/zara-privacy-dev.db*

# ─── Smoke test (stdio) ──────────────────────────────────────────────────────

smoke:
	@echo '{"jsonrpc":"2.0","id":1,"method":"list_tools"}' | $(GO) run ./cmd/server/ --stdio 2>/dev/null | python3 -m json.tool > /dev/null && echo "✓ list_tools OK"
	@echo '{"jsonrpc":"2.0","id":2,"method":"call_tool","params":{"name":"scan_context","arguments":{"text":"test@email.com"}}}' | $(GO) run ./cmd/server/ --stdio 2>/dev/null | python3 -m json.tool > /dev/null && echo "✓ scan_context OK"
	@echo "✓ All smoke tests passed"

# ─── Help ─────────────────────────────────────────────────────────────────────

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@echo "  build           Build binary for current OS"
	@echo "  build-linux     Cross-compile for Linux amd64"
	@echo "  build-darwin    Cross-compile for macOS arm64"
	@echo ""
	@echo "Run:"
	@echo "  run             Build and run HTTP server"
	@echo "  run-stdio       Build and run stdio mode"
	@echo "  run-dev         Run in dev mode with debug logging"
	@echo ""
	@echo "Test:"
	@echo "  test            Run all tests with race detection"
	@echo "  test-coverage   Generate coverage report"
	@echo ""
	@echo "Deploy:"
	@echo "  install         Build and install to /usr/local/bin"
	@echo "  uninstall       Remove from /usr/local/bin"
	@echo ""
	@echo "Skill:"
	@echo "  install-skill   Install skill to all agent directories"
	@echo "  uninstall-skill Remove skill from agent directories"
	@echo ""
	@echo "Other:"
	@echo "  lint            Run go vet and staticcheck"
	@echo "  clean           Remove build artifacts"
	@echo "  smoke           Quick stdio smoke test"
