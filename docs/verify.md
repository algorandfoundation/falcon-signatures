# falcon verify

Verify a Falcon-1024 signature against a message and public key.

- Flags:
  - `--key <file>`: path to a keypair file (may contain only a public key)
  - `--in <file>` or `--msg <string>`: message that was signed
  - `--hex`: if set, treat message as hex-encoded bytes; otherwise UTF-8 string
  - `--sig <file>` or `--signature <hex>`: signature to verify

## Examples

Verify a signature from files; treat message as UTF-8:

```bash
falcon verify --key pubkey.json --in message.txt --sig signature.sig
```


Verify using inline message and inline signature; treat message as hex:

```bash
falcon verify --key pubkey.json --msg deadbeefcafebabe --hex --signature abcd1234...
```
