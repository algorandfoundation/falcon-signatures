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

#### Build and run with Docker

If you prefer not to install Go locally, you can build and run `falcon` with Docker:

```bash
docker build -t falcon .
docker run --rm falcon help
```

To use local files such as keypairs, signatures, or message files, mount the current directory into the container:

```bash
docker run --rm -v "$PWD:/work" -w /work falcon create --out mykeys.json
docker run --rm -v "$PWD:/work" -w /work falcon sign --key mykeys.json --msg "hello world"
```

See [`docs/docker.md`](docs/docker.md) for more Docker examples.

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
| [`Docker usage`](docs/docker.md) | Build and run `falcon` with Docker |

---

## Key Management

`falcon create` generates keys using 24-word BIP-39 mnemonics by default for easy recovery.

- **Default:** 256-bit entropy with mnemonic (recoverable)
- **High security:** 384-bit entropy without mnemonic (`--no-mnemonic`)
- **Deterministic:** Generate from custom seed (`--seed`)

See [`falcon create`](docs/create.md) documentation for details.

---

## Security Considerations

External libraries or SDKs integrating the Logic Signature (LSig) template without
this CLI must implement the following LSig address rejection-sampling predicate:

```text
Reject the LSig address if the 32-byte value decodes to any Edwards25519 curve point,
including non-canonical encodings, small-order points, and points outside the prime-order
subgroup.
```

The predicate is deliberately broader than strict point validation as a public key.
**Do not** implement this with Ed25519 libraries that admit only the strict decoding
rules, such as libsodium/PyNaCl `crypto_core_ed25519_is_valid_point()`.

This repository uses `filippo.io/edwards25519.Point.SetBytes` to implement the predicate.

---

## Integration Tests

Golden fixtures for external integration tests are in [`algorand/testdata/lsig_address_kat.json`](./algorand/testdata/lsig_address_kat.json).

The fixture includes raw Edwards25519 decode cases and a full LSig derivation case
where counter `0` must be rejected and counter `1` must be selected. See
[`algorand/testdata/README.md`](./algorand/testdata/README.md) for regeneration
instructions.

---

## License

This project is licensed under the **AGPL**.
