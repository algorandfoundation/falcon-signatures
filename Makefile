GO ?= go
PKG := ./cmd/falcon
BIN := falcon

.PHONY: build test vet format lint check all

build: ## Build the CLI binary to ./falcon
	$(GO) build -o $(BIN) $(PKG)

test: ## Run tests with race detector and coverage
	$(GO) test -race -cover ./...

vet: ## Static analysis
	$(GO) vet ./...

format: ## Format code (goimports if available, then gofmt)
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true
	$(GO) fmt ./...
	gofmt -s -w .

lint: ## Run golangci-lint
	golangci-lint run

check: ## Run vet, lint, and tests (no writes)
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test

all: ## Format, vet, lint, test, then build
	@$(MAKE) format
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) build
