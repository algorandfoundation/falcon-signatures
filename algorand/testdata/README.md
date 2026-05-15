# Algorand LSig Address Fixtures

`lsig_address_kat.json` is a language-neutral fixture for integration testing of
the Falcon LSig template (without using address rejection-sampling of this CLI).

The required rejection-sampling predicate is:

```text
Reject the LSig address if the 32-byte value decodes to any Edwards25519 curve point,
including non-canonical encodings, small-order points, and points outside the prime-order
subgroup.
```

The fixture includes:

- `edwards25519_decode_cases`: raw 32-byte values to test the required predicate vs. RFC 8032 public-key validation (e.g., libsodium's `crypto_core_ed25519_is_valid_point`).
- `lsig_derivation`: a complete Falcon public key and LSig derivation case where counter `0` is rejected and counter `1` is selected.
