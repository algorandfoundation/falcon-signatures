# falcon sign

Sign a message using a Falcon-1024 private key.

- Flags:
  - `--key <file>`: path to a keypair file
  - `--in <file>` or `--msg <string>`: message to sign (one required)
  - `--hex`: if set, treat message input as hex-encoded bytes; otherwise UTF-8 string
  - `--out <file>`: write the signature to a file; otherwise printed to stdout

## Examples

Sign a text string with a key file:

```bash
falcon sign --key mykeys.json --msg "hello world"
```

Sign a file in hex format and write the signature to disk:

```bash
falcon sign --key mykeys.json --in message.bin --hex --out payload.sig
```
