# Repository Guidelines

## Project Structure & Module Organization
- `main.go`: CLI entrypoint wiring commands and flags.
- `falcon.go`: Falcon-1024 logic and helpers (deterministic signing).
- `falcon_test.go`: Unit tests for core behaviors.
- `go.mod`, `go.sum`: Module metadata and dependencies.
- `README.md`: Usage and background.

## Build, Test, and Development Commands
- Build: `go build -o falcon .` produces the CLI binary in the repo root.
- Test: `go test ./...` runs all tests; add `-race` and `-cover` for race/coverage: `go test -race -cover ./...`.
- Vet: `go vet ./...` performs static checks.

## Coding Style & Naming Conventions
- Formatting: Use `gofmt -s -w .` (required). Prefer `goimports` for imports.
- Indentation: Tabs (Go default). Line length: keep readable (~100–120 chars).
- Naming: Exported identifiers use PascalCase; package-internal use lowerCamelCase. Keep CLI commands short, verb-first.
- Errors: Return `error`; avoid `panic` in library code. Wrap with context where helpful.
- Files: Keep CLI concerns in `main.go`; cryptographic logic stays in `falcon.go`.

## Testing Guidelines
- Framework: Go `testing` package with table-driven tests.
- Files: Name tests `*_test.go`; functions as `TestXxx`.
- Determinism: Verify signatures are deterministic for the same key/message; include negative cases.
- Coverage: Aim for meaningful coverage on key paths. Run `go test -cover ./...` locally.

## Commit & Pull Request Guidelines
- Commits: Use concise, imperative subject lines (e.g., "add verify subcommand"). Group logical changes; keep diffs focused.
- PRs: Provide a clear description, rationale, and usage examples (CLI commands). Link related issues. Include tests for new behavior and update `README.md` if flags or commands change.
- Checks: Ensure `go build`, `go vet`, and `go test -race -cover` pass before requesting review.

## Security & Configuration Tips
- Keys: Never commit private keys or test vectors containing secrets.
- Reproducibility: Prefer deterministic code paths; avoid time- or rand-dependent behavior in library logic.
- Go version: Use the version pinned in `go.mod` and test on the latest stable Go locally.
