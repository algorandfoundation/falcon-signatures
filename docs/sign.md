# falcon sign

Sign a message using a Falcon-1024 private key.

#### Arguments
  - Required
    - `--key <file>`: path to a keypair file
    - one of: `--in <file>` or `--msg <string>`: message to sign
  - Optional
    - `--hex`: treat message input as hex-encoded bytes; otherwise UTF-8 string
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
