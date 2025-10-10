# falcon create

Generate a new FALCON-1024 keypair.

You have three options for key generation:
1. Randomly generate a 24-word BIP-39 mnemonic and derive the keypair from it (default), which provides 256 bits of entropy.
2. Randomly generate a new keypair without mnemonic with 384 bits of entropy (using `--no-mnemonic`).
3. Deterministically derive a keypair from a seed passphrase (using `--seed`), with entropy based on the strength of your passphrase.

#### Arguments
  - Optional:
    - `--out <file>`: write the keypair to a JSON file; otherwise the full JSON is printed to stdout
    - `--mnemonic-passphrase <string>`: optional BIP-39 passphrase to mix into seed derivation
      - The passphrase is stored in the output JSON when provided so downstream commands can recover the key without prompting.
      - Leave it blank to generate a mnemonic without a passphrase.
    - `--no-mnemonic`: generate a random keypair without mnemonic (384 bits of entropy)
    - `--seed <text>`: deterministically derive the keypair from a text passphrase
      - The seed is processed with PBKDF2-HMAC-SHA-512 (100,000 iterations) and a fixed salt to derive a 48-byte keygen seed.
      - Tip: unless you know what you're doing, you are likely better off using a random key or a 24 word mnemonic.
    - `--from-mnemonic "<24 words>"`: recover the keypair from a 24-word BIP-39 mnemonic

## Examples

Create a random keypair and print to stdout:

```bash
falcon create
```

Create a random keypair and save it to a file:

```bash
falcon create --out mykeys.json
```

Create a random keypair with a mnemonic passphrase and save it to a file:

```bash
falcon create --mnemonic-passphrase "TREZOR" --out mykeys.json
```

Recover a keypair from an existing mnemonic (use all 24 words separated by spaces):

```bash
falcon create --from-mnemonic "word1 word 2 ... word 24" --mnemonic-passphrase "TREZOR" --out recovered.json
```

Create a random keypair without a mnemonic (384-bit entropy) and write it to a file:

```bash
falcon create --no-mnemonic --out strongkeys.json
```

Create a deterministic keypair from a given seed phrase:

```bash
falcon create --seed "correct horse battery staple"
```

Create a deterministic keypair from a seed phrase and save it:

```bash
falcon create --seed "my 12 word seed phrase ..." --out mykeys.json
```

## Security Notes

- **Mnemonic files contain full recovery material.** Store them as securely as you would store private keys.
- **File permissions:** Key files are automatically created with `0600` permissions (read/write for owner only).
- **Passphrase strength:** If using `--seed`, choose a strong passphrase (12+ random words recommended).
- **Backup:** Write down your mnemonic and store it securely offline.
