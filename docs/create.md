# falcon create

Generate a new Falcon-1024 keypair.

#### Arguments
  - Optional:
    - `--seed <text>`: deterministically derive the keypair from a text seed/passphrase
      - The seed is processed with PBKDF2-HMAC-SHA-512 (100,000 iterations) and a fixed salt to derive a 48-byte keygen seed.
      - Tip: choose a seed phrase of 12+ random words for better security.
      - Warning: low-entropy or common phrases are guessable. Use a high-entropy, truly random 12+ word phrase if you need secrecy. The fixed salt is for reproducibility, not password hardening.
    - `--out <file>`: write the keypair to a JSON file; otherwise prints to stdout

## Examples

Create a random keypair and print to stdout:

```bash
falcon create
```

Create a deterministic keypair from a given seed phrase:

```bash
falcon create --seed "correct horse battery staple"
```

Create a keypair and save it to a file:

```bash
falcon create --out mykeys.json
```

Create a deterministic keypair from a seed phrase and save it:

```bash
falcon create --seed "my 12 word seed phrase ..." --out mykeys.json
```
