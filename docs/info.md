# falcon info

Display information about a keypair file. Prints the public key, private key, and mnemonic (if present).

If the file contains a mnemonic without explicit keys, this command will derive them from the mnemonic.

**Note:** If the file contains a mnemonic without a passphrase, you must provide the passphrase via `--mnemonic-passphrase` to derive the keys.

#### Arguments
  - Required
    - `--key <file>`: path to a keypair file
  - Optional
    - `--mnemonic-passphrase <string>`: mnemonic passphrase if used and key file omits it (when using mnemonic-only files)


## Examples

Inspect a keypair file:

```bash
falcon info --key mykeys.json
```
