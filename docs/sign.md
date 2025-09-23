# falcon sign

Sign a message using a FALCON-1024 private key.

#### Arguments
  - Required
    - `--key <file>`: path to a keypair file
    - one of: `--in <file>` or `--msg <string>`: message to sign
  - Optional
    - `--hex`: treat message input as hex-encoded bytes; otherwise UTF-8 string
    - `--out <file>`: write raw signature bytes to file (if omitted, print hex to stdout)

## Examples

Sign a text string with a key file:

```bash
falcon sign --key mykeys.json --msg "hello world"
```

Sign a hex-encoded message stored in a text file and write the raw signature to disk:

```bash
falcon sign --key mykeys.json --in message.hex --hex --out payload.sig
```
