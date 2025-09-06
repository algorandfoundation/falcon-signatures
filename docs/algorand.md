# falcon algorand

These commands let users simulate post-quantum accounts on the Algorand blockchain using Falcon signatures.

Under the hood, a logicsig signature is created for the user's Falcon signature and must be used to authorize transactions.

The workflow for the user is as follows:
1. Generate a Falcon keypair.
2. Derive an associated Algorand address (controlled under the hood by a logicsig).
3. Deposit funds to the Algorand address as usual (any wallet can be used for this).
4. To spend funds, use the provided commands to send transactions signed by the Falcon private key.

The subcommands are:
- `falcon algorand address`: Derive an Algorand address from a Falcon public key.
- `falcon algorand send`: Send algorand assets from a Falcon-controlled address.

----

### falcon algorand address

Generate an Algorand address controlled by a Falcon public key.

#### Arguments
  - Required
    - `--key <file>`: path to a keypair file (may contain only a public key)
  - Optional
    - `--out <file>`: path to output file; otherwise prints to stdout

#### Examples
Generate an Algorand address from a Falcon public key and print to stdout:

```bash
falcon algorand address --key pubkey.json
```
Generate an Algorand address from a Falcon keypair and save to a file:

```bash
falcon algorand address --key keypair.json --out address.txt
```

----

### falcon algorand send

Send algorand assets from an Algorand address controlled by a Falcon keypair.

#### Arguments
  - Required
    - `--key <file>`: path to a Falcon keypair file (must contain private key)
    - `--to <address>`: Algorand address to send assets to
    - `--amount <number>`: amount of microAlgos to send (or asset units if `--asset-id` is set)
  - Optional
    - `--fee <number>`: transaction fee in microAlgos (default: minimum network transaction fee)
    - `--asset-id <number>`: asset ID to send (default is Algos)
    - `--note <string>`: optional note to include in the transaction
    - `--network <name>`: network to use: `mainnet` (default), `testnet`, `betanet`, `devnet`

#### Examples
Send 1 Algo (1,000,000 microAlgos) to an address using a Falcon keypair:
```bash
falcon algorand send --key keypair.json --to ALGOADDRESS12345 --amount 1000000
```

Send 100 units of an asset with ID 123456 to an address with a custom fee and note:
```bash
falcon algorand send --key keypair.json --to ALGOADDRESS12345 --amount 100 --asset-id 123456 --fee 2000 --note "Payment for services"
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
if environment variable `ALGOD_URL` is set, then the program will use that Algorand node (reading `ALGOD_TOKEN` as well if set).<br>
If not set, Nodely endpoints will be used.<br>
For `--network devnet`, `ALGOD_URL` (and optionally `ALGOD_TOKEN`) must be set to point to your node.
