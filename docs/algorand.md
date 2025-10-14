# falcon algorand

These commands let users simulate post-quantum accounts on the Algorand blockchain using FALCON signatures.

Under the hood, a logicsig signature is created for the user's FALCON signature and must be used to authorize transactions (see [implementation details](https://github.com/algorandfoundation/falcon-signatures/blob/main/algorand/doc.go)).

The workflow for the user is as follows:
1. Generate a FALCON keypair.
2. Derive an associated Algorand address (controlled under the hood by a logicsig).
3. Deposit funds to the Algorand address as usual (any wallet can be used for this).
4. To spend funds, use the provided commands to send transactions signed by the FALCON private key.

The subcommands are:
- `falcon algorand address`: Derive an Algorand address from a FALCON public key.
- `falcon algorand send`: Send Algos from a FALCON-controlled address.

----

### falcon algorand address

Generate an Algorand address controlled by a FALCON public key.

#### Arguments
  - Required
    - `--key <file>`: path to keypair file (public key sufficient; mnemonic-only files supported)
  - Optional
    - `--out <file>`: path to output file; otherwise prints to stdout
    - `--mnemonic-passphrase <string>`: mnemonic passphrase when the key file omits it

#### Examples
Generate an Algorand address from a FALCON public key and print to stdout:

```bash
falcon algorand address --key pubkey.json
```
Generate an Algorand address from a FALCON keypair and save to a file:

```bash
falcon algorand address --key keypair.json --out address.txt
```

----

### falcon algorand send

Send Algos from an Algorand address controlled by a FALCON keypair.

#### Arguments
  - Required
    - `--key <file>`: path to keypair file (must include private key; mnemonic-only files supported)
    - `--to <address>`: Algorand address to send to
    - `--amount <number>`: amount of microAlgos to send
  - Optional
    - `--fee <number>`: transaction fee in microAlgos (default: minimum network transaction fee)
    - `--note <string>`: optional note to include in the transaction
    - `--network <name>`: network to use: `mainnet` (default), `testnet`, `betanet`, `devnet`
    - `--algod-url <string>`: override algod endpoint URL (sets `ALGOD_URL`; pass `""` to reset to defaults)
    - `--algod-token <string>`: algod API token (sets `ALGOD_TOKEN`; requires `--algod-url`; pass `""` to clear)
    - `--mnemonic-passphrase <string>`: mnemonic passphrase if used and key file omits it (when using mnemonic-only files)

#### Examples
Send 1 Algo (1,000,000 microAlgos) to an address using a FALCON keypair:
```bash
falcon algorand send --key keypair.json --to ALGOADDRESS12345 --amount 1000000
```

Send 1 Algo with a custom fee and note:
```bash
falcon algorand send --key keypair.json --to ALGOADDRESS12345 --amount 1000000 --fee 2000 --note "Payment for services"
```

Send on TestNet using suggested params (default fee behavior):
```bash
falcon algorand send --key keypair.json --to TESTNETADDR... --amount 1000000 --network testnet
```

Send with an explicit flat fee of 0 microAlgos (for testing):
```bash
falcon algorand send --key keypair.json --to TESTNETADDR... --amount 500000 --fee 0 --network testnet
```

**Note**:<br>
Pass `--algod-url`/`--algod-token` to use your preferred algod endpoints.<br>
If not passed, the env vars `ALGOD_URL` and `ALGOD_TOKEN` will be used.<br>
If unset or empty, Nodely endpoints will be used by default.<br>
You can also pass `--algod-url ""` to reset to the default Nodely endpoints.<br>
For `--network devnet`, provide an algod endpoint via either the flags or the `ALGOD_URL` environment variable (and `ALGOD_TOKEN` if required by your node).
