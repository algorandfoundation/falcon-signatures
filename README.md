# falcon – a CLI tool to explore Falcon signatures

This repository introduces the **falcon** CLI tool, designed to facilitate exploration of the Falcon signature scheme.

This tool is part of the R&D work to make the Algorand blockchain quantum-safe, but it can also be used independently to explore Falcon signatures.

The tool implements the **Falcon-1024** scheme, based on [this implementation](https://github.com/algorand/falcon), using **deterministic signing** (which means signing a message with a given private key will always produce the same signature).

### Key and signature sizes (Falcon-1024)

| Key type    | Size        |
|-------------|-------------|
| Public key  | 1,793 bytes |
| Private key | 2,305 bytes |
| Signature   | 1,538 bytes (uncompressed) |

Falcon-1024 targets **NIST security level 5** — i.e., *at least as hard to break as brute-forcing AES-256* (~256-bit classical security).
That’s the highest NIST Post-Quantum Cryptography category for signatures.

---

## Installation

You need Go installed.

To install directly:

```bash
go install github.com/algorandfoundation/falcon-signatures@latest
```

This will place the `falcon` binary in your Go bin directory (usually `$GOPATH/bin`).
Make sure that directory is on your `PATH`.

Verify installation:

```bash
falcon help
```

---

### Build from source

```bash
git clone https://github.com/algorandfoundation/falcon-signatures.git
cd falcon-signatures
make build
```

This creates the `falcon` binary in the current directory.

You can also run the tests:

```bash
make test
```

Run static analysis:

```bash
make vet
```

---

## Usage

Available commands:

```
falcon create   : Create a new keypair
falcon sign     : Sign a message
falcon verify   : Verify a signature for a message
falcon info     : Display information about a keypair file
falcon help     : Show help
```

Detailed command syntax lives in per-command docs:

- [`falcon create`](docs/create.md)
- [`falcon sign`](docs/sign.md)
- [`falcon verify`](docs/verify.md)
- [`falcon info`](docs/info.md)
- [`falcon help`](docs/help.md)

---

## License

This project is licensed under the **AGPL**.
