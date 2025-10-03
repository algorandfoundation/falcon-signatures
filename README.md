# falcon – a CLI tool to explore FALCON signatures

This repository introduces the **falcon** CLI tool, designed to facilitate exploration of the FALCON signature scheme.

This tool is part of the R&D work to make the Algorand blockchain quantum-safe, but it can also be used independently to explore FALCON signatures.

The tool implements the **FALCON-1024** scheme, based on [this implementation](https://github.com/algorand/falcon), using **deterministic signing** (which means signing a message with a given private key will always produce the same signature).

| Key type    | Size        |
|-------------|-------------|
| Public key  | 1,793 bytes |
| Private key | 2,305 bytes |
| Signature   | 1,538 bytes (uncompressed) |

FALCON-1024 targets **NIST security level 5** — i.e., *at least as hard to break as brute-forcing AES-256* (~256-bit classical security).
That’s the highest NIST Post-Quantum Cryptography category for signatures.

---

## Installation


#### Install via `go install`

If you have Go1.21+ installed, you can install directly with:

```bash
go install github.com/algorandfoundation/falcon-signatures/cmd/falcon@latest
```

This places the `falcon` binary in your Go bin directory (usually `$GOBIN` or `$GOPATH/bin`).
Make sure that directory is on your `PATH`.

Verify installation:

```bash
falcon help
```

---

#### Pre-built binaries

Pre-built binaries are available on the [releases page](https://github.com/algorandfoundation/falcon-signatures/releases)

---

#### Build from source

You need Go1.25+ to build from source:

```bash
git clone https://github.com/algorandfoundation/falcon-signatures.git
cd falcon-signatures
make build
```

This creates the `falcon` binary at `./build/falcon`.

Run `make help` to see all available commands.

---

## Usage

Available commands:

| Command | Description |
| --- | --- |
| [`falcon create`](docs/create.md) | Create a new keypair |
| [`falcon sign`](docs/sign.md) | Sign a message |
| [`falcon verify`](docs/verify.md) | Verify a signature for a message |
| [`falcon info`](docs/info.md) | Display information about a keypair file |
| [`falcon version`](docs/version.md) | Show the CLI build version |
| [`falcon help`](docs/help.md) | Show help |
| [`falcon algorand`](docs/algorand.md) | Algorand-specific commands |

---

## License

This project is licensed under the **AGPL**.
