GO ?= go
PKG := ./cmd/falcon
OUTPUT_DIR := $(CURDIR)/build
TOOLS_DIR := $(CURDIR)/.tools

FALCON_BIN := $(OUTPUT_DIR)/falcon
GOLANGCILINT_BIN := $(TOOLS_DIR)/golangci-lint
GOIMPORTS_BIN := $(TOOLS_DIR)/goimports

.DEFAULT_GOAL := help
.PHONY: all build check clean cleantools cleanall format help install install-goimports install-golangci-lint test test-integration tidy tools vet

# Without this, 'go test -race' spits out "malformed LC_DYSYMTAB" warnings.
# Info: https://github.com/golang/go/issues/61229#issuecomment-1988965927
# Scheduled to be fixed in Go 1.26
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
	export CGO_LDFLAGS ?= -Wl,-w
endif

all: check test build ## tidy, format, vet, lint, test, then build

build: ## Build the CLI binary to ./falcon
	$(GO) build -o $(FALCON_BIN) $(PKG)

check: tidy format vet lint ## Run format, vet, and lint

clean: ## Remove the build directory
	rm -rf $(FALCON_BIN)

cleantools: ## Remove the downloaded tooling
	rm -rf $(TOOLS_DIR)

cleanall: clean cleantools ## Remove everything

format: $(GOIMPORTS_BIN) ## Format code
	$(GOIMPORTS_BIN) -w .
	$(GO)fmt -l -s -w .

help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install the binary
	$(GO) install $(PKG)

lint: $(GOLANGCILINT_BIN) ## Run golangci-lint
	$(GOLANGCILINT_BIN) run

# Unit tests only (test files without //go:build integration header)
test: ## Run unit tests
	$(GO) test -race -cover ./...


# Unit and integration tests (also files with //go:build integration header)
test-integration: build ## Run unit + integration tests
	$(GO) test -race -cover -tags=integration ./...

tidy: ## Tidy up go.mod and go.sum files
	$(GO) mod tidy
	@# Verify that the git repository is clean after tidy.
	@if ! git diff --quiet go.mod go.sum; then \
		echo "==> Please run 'go mod tidy' and commit the changes."; \
		exit 1; \
	fi

tools: $(GOLANGCILINT_BIN) $(GOIMPORTS_BIN) ## Install development tooling

# install golangci-lint regardless of what you have installed
install-golangci-lint:
	@echo "Installing golangci-lint to $(GOLANGCILINT_BIN)"
	@GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0

# golangci warns against using this method of install, so if you
# already have golangci-lint available we'll use that instead.
$(GOLANGCILINT_BIN):
	@if command -v golangci-lint >/dev/null; then \
		GOLANGCILINT_SYSTEM=$$(command -v golangci-lint); \
		mkdir -p $(TOOLS_DIR); \
		ln -s "$$GOLANGCILINT_SYSTEM" $(GOLANGCILINT_BIN); \
		echo "Existing golangci-lint installation found..."; \
		echo "Creating symlink in $(GOLANGCILINT_BIN)"; \
	else \
		$(MAKE) install-golangci-lint; \
	fi

install-goimports: $(GOIMPORTS_BIN)

$(GOIMPORTS_BIN):
	@echo "Installing goimports to $(GOIMPORTS_BIN)"
	@GOBIN=$(TOOLS_DIR) go install golang.org/x/tools/cmd/goimports@v0.37.0

vet: ## Static analysis
	$(GO) vet ./...
