GO ?= go
PKG := .
BIN := falcon

.PHONY: build test vet

build: ## Build the CLI binary to ./falcon
	$(GO) build -o $(BIN) $(PKG)

test: ## Run tests with race detector and coverage
	$(GO) test -race -cover ./...

vet: ## Static analysis
	$(GO) vet ./...
