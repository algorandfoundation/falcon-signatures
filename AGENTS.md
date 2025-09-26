# Repository Guidelines

## Project Structure & Module Organization
- `cmd/falcon/main.go`: CLI binary entrypoint invoking the reusable CLI package.
- `cli/`: CLI package with subcommand dispatchers and shared helpers.
  - `cli/cli.go`: Top-level dispatcher exposing `Main`/`Run`.
  - `cli/create.go`, `cli/sign.go`, `cli/verify.go`, `cli/info.go`, `cli/algorand.go`, `cli/help.go`: Implement subcommands.
  - `cli/utils.go`: Shared helpers (hex parsing, atomic file writes, key JSON I/O).
- `cli/*_test.go`: Tests validating CLI behavior (`create_test.go`, `sign_test.go`, `verify_test.go`, `info_test.go`).
- `falcongo/falcon.go`: Falcon-1024 primitives and helpers (deterministic signing via SHA-512/256 digesting + compressed signatures).
- `falcongo/falcon_test.go`: Unit tests for core Falcon behaviors and sizes.
- `algorand/`: Algorand integration package for FALCON-based accounts and logicsig derivation.
  - `address.go`: Algorand address derivation from FALCON public keys.
  - `address_test.go`: Tests for address derivation functionality.
  - `algoutils.go`: Utility functions for Algorand operations.
  - `send.go`: Transaction sending functionality.
  - `doc.go`: Package documentation explaining FALCON-based Algorand accounts.
- `utils.go`: Shared helpers (hex parsing, atomic file writes, key JSON I/O, fatal helpers).
- `integration/`: Integration tests for end-to-end functionality.
- `docs/*.md`: Per-command usage docs (`create.md`, `sign.md`, `verify.md`, `info.md`, `help.md`, `algorand.md`).
- `README.md`: Overview, installation, usage summary, and links to docs.
- `Makefile`: Common developer tasks (`build`, `test`, `vet`, `format`).
- `go.mod`, `go.sum`: Module metadata and dependencies.
- `LICENSE`: Project license.

## Build, Test, and Development Commands
- Build: `go build -o build/falcon ./cmd/falcon` produces the CLI binary at `build/falcon`.
- Make targets:
  - `make build`: build to `build/falcon`.
  - `make test`: run `go test -race -cover ./...`.
  - `make vet`: run `go vet ./...`.
  - `make format`: run `goimports` (if present), `go fmt`, and `gofmt -s -w .`.
- Direct test invocation: `go test ./...` (add `-race -cover` locally for more checks).
 - After making changes: run `make format` before committing to ensure consistent formatting and imports.

## CLI Conventions
- Subcommands: `create`, `sign`, `verify`, `info`, `algorand`, `help` (see `docs/*.md` for details).
- Exit codes: `0` success; `1` for `verify` when signature is invalid; `2` for usage, parse, or I/O errors.
- Key JSON format: `{ "public_key": "<hex>", "private_key": "<hex>" }` (lowercase hex when written). Either field may be absent.
- Hex handling: `parseHex` accepts optional `0x` prefix and odd nibble padding; `--hex` flag treats message as hex bytes.
- Deterministic signing: messages are hashed with SHA-512/256 before signing; with a fixed key and message the compressed signature is deterministic.
- I/O: `--out` writes to files atomically; otherwise output prints to stdout.

## Coding Style & Naming Conventions
- Formatting: Use `gofmt -s -w .` (required). Prefer `goimports` for imports.
- Indentation: Tabs (Go default). Line length: keep readable (~100–120 chars).
- Naming: Exported identifiers use PascalCase; package-internal use lowerCamelCase. Keep CLI commands short, verb-first.
- Errors: Return `error`; avoid `panic` in library code. Wrap with context where helpful.
  - Note: cryptographic seeding uses `crypto/rand`; an unrecoverable failure there triggers a panic as it is considered fatal.
- Separation: Keep CLI concerns in the `cli/` package; cryptographic logic stays in `falcongo/`; Algorand-specific logic in `algorand/`; shared CLI helpers live in `cli/utils.go`.

## Testing Guidelines
- Framework: Go `testing` package; table-driven where appropriate.
- Files: Name tests `*_test.go`; functions as `TestXxx`.
- Determinism: Verify signatures are deterministic for the same key/message; include negative cases and CLI flag validation.
- Coverage: Aim for meaningful coverage on key paths. Run `go test -race -cover ./...` locally.
- CLI tests: Prefer using helpers to capture stdout/stderr and validate exit codes and outputs.

## Commit & Pull Request Guidelines
- Commits: Use concise, imperative subject lines (e.g., "add verify subcommand"). Group logical changes; keep diffs focused.
- PRs: Provide a clear description, rationale, and usage examples (CLI commands). Link related issues. Include tests for new behavior and update `README.md`/`docs/*.md` if flags or commands change.
- Checks: Ensure `go build`, `go vet`, and `go test -race -cover` pass before requesting review.

## Security & Configuration Tips
- Keys: Never commit private keys or test vectors containing secrets.
- Seed derivation: `create --seed` uses PBKDF2-HMAC-SHA-512 (100,000 iters) with a fixed salt to derive a 48-byte seed for keygen. This is for reproducibility, not password hardening—use high-entropy seeds.
- Reproducibility: Prefer deterministic code paths; avoid time- or rand-dependent behavior in library logic.
- Go version: Use the version pinned in `go.mod` and test on the latest stable Go locally.
