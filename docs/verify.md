# falcon verify

Verify a FALCON-1024 signature against a message and public key.

#### Arguments
  - Required
    - `--key <file>`: path to keypair file (public key sufficient; mnemonic-only files supported)
    - one of: `--in <file>` or `--msg <string>`: message that was signed
    - one of: `--sig <file>` or `--signature <hex>`: signature to verify (`--sig` expects raw signature bytes; `--signature` expects lowercase hex)
  - Optional
    - `--hex`: treat message as hex-encoded bytes; otherwise UTF-8 string
    - `--mnemonic-passphrase <string>`: mnemonic passphrase if used and key file omits it (when using mnemonic-only files)

## Examples

Verify a signature from files; treat message as UTF-8:

```bash
falcon verify --key pubkey.json --in message.txt --sig signature.sig
```


Verify using inline message and inline signature; treat message as hex:

```bash
falcon verify --key pubkey.json --msg deadbeefcafebabe --hex --signature abcd1234...
```
