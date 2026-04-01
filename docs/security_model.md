# Security Model

## Base Assumptions

This assurance lane adds assumptions beyond the base SKY verifier:

1. the attestation construction is sound
2. the attestation verifier implementation matches the attestation format
3. the Solidity verifier and registry contracts implement the intended checks

## Current Status

- attestation code: reference implementation
- contract surfaces: reference implementation with local positive and tamper-path
  coverage for the current AIR/FRI scheme
- proof binding: the verifier now binds each STARK proof to the canonical bundle
  hash through the Fiat-Shamir transcript, so a valid proof cannot be replayed
  against an unrelated bundle hash without failing verification
- malformed attestation defense: the Python verifier now rejects empty proof
  payloads, proof-count mismatches, and bundle-binding mismatches instead of
  accepting shape-only attestations
- production posture: requires independent assurance review before buyer claims are upgraded
