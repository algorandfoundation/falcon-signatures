GO ?= go
PKG := ./cmd/falcon
BIN := falcon

.DEFAULT_GOAL := help
.PHONY: all build check clean format help lint test test-integration vet

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
	export CGO_LDFLAGS ?= -Wl,-w
endif

# Not included: test-integration, clean
all: ## Format, vet, lint, test, then build
	@$(MAKE) format
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) build

build: ## Build the CLI binary to ./falcon
	$(GO) build -o $(BIN) $(PKG)

check: ## Run format, vet, lint, and test
	@$(MAKE) format
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test

clean: ## Remove the built binary
	rm -f $(BIN)

format: ## Format code (goimports if available, then gofmt)
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true
	$(GO) fmt ./...
	gofmt -s -w .

help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

lint: ## Run golangci-lint
	golangci-lint run

# Unit tests only (test files without //go:build integration header)
test: ## Run unit tests
	$(GO) test -race -cover ./...

# Unit and integration tests (also files with //go:build integration header)
test-integration: ## Run unit + integration tests
	$(GO) test -race -cover -tags=integration ./...

vet: ## Static analysis
	$(GO) vet ./...
