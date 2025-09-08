# Repository Guidelines

## Project Structure & Module Organization
- `main.go`: CLI entrypoint dispatching subcommands and flags.
- `cmd_create.go`: Implement `falcon create` (keypair generation, optional seed, file output).
- `cmd_sign.go`: Implement `falcon sign` (message input, hex mode, file/stdout output).
- `cmd_verify.go`: Implement `falcon verify` (message + signature sources, validity result, exit codes).
- `cmd_info.go`: Implement `falcon info` (inspect key JSON and print fields).
- `cmd_help.go`: Top-level and per-command help text routing.
- `falcon.go`: Falcon-1024 primitives and helpers (deterministic signing via SHA-512/256 digesting + compressed signatures).
- `utils.go`: Shared helpers (hex parsing, atomic file writes, key JSON I/O, fatal helpers).
- `falcon_test.go`: Unit tests for core Falcon behaviors and sizes.
- `cmd_*.go` tests: `cmd_create_test.go`, `cmd_sign_test.go`, `cmd_verify_test.go`, `cmd_info_test.go` validate CLI behavior.
- `docs/*.md`: Per-command usage docs (`create.md`, `sign.md`, `verify.md`, `info.md`, `help.md`).
- `README.md`: Overview, installation, usage summary, and links to docs.
- `Makefile`: Common developer tasks (`build`, `test`, `vet`, `format`).
- `go.mod`, `go.sum`: Module metadata and dependencies.
- `LICENSE`: Project license.

## Build, Test, and Development Commands
- Build: `go build -o falcon .` produces the CLI binary in the repo root.
- Make targets:
  - `make build`: build to `./falcon`.
  - `make test`: run `go test -race -cover ./...`.
  - `make vet`: run `go vet ./...`.
  - `make format`: run `goimports` (if present), `go fmt`, and `gofmt -s -w .`.
- Direct test invocation: `go test ./...` (add `-race -cover` locally for more checks).
 - After making changes: run `make format` before committing to ensure consistent formatting and imports.

## CLI Conventions
- Subcommands: `create`, `sign`, `verify`, `info`, `help` (see `docs/*.md` for details).
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
- Separation: Keep CLI concerns in `cmd_*.go` and `main.go`; cryptographic logic stays in `falcon.go`; shared helpers in `utils.go`.

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
