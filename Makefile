GO ?= go
PKG := ./cmd/falcon
BIN := falcon

.PHONY: build test vet format

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
