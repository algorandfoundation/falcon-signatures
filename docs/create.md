# falcon create

Generate a new Falcon-1024 keypair.

#### Arguments
  - Optional:
    - `--seed <hex>`: deterministically derive the keypair from a hex-encoded seed
    - `--out <file>`: write the keypair to a JSON file; otherwise prints to stdout

## Examples

Create a random keypair and print to stdout:

```bash
falcon create
```

Create a deterministic keypair from a given seed:

```bash
falcon create --seed deadbeefcafebabe
```

Create a keypair and save it to a file:

```bash
falcon create --out mykeys.json
```

Create a deterministic keypair from a seed and save it:

```bash
falcon create --seed deadbeefcafebabe --out mykeys.json
```
