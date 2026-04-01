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
- corpus breadth: local positive corpus coverage now spans multiple reducer shapes
  (`trivial_true`, identity-style reduction, and K-rule reduction), not just a
  single fixture
- proof binding: the verifier now binds each STARK proof to the canonical bundle
  hash through the Fiat-Shamir transcript, so a valid proof cannot be replayed
  against an unrelated bundle hash without failing verification
- malformed attestation defense: the Python verifier now rejects empty proof
  payloads, proof-count mismatches, and bundle-binding mismatches instead of
  accepting shape-only attestations
- gas regression gate: local verification now enforces explicit gas ceilings for
  the main positive and tamper/binding paths so on-chain cost drift becomes a
  release-blocking failure
- production posture: requires independent assurance review before buyer claims are upgraded
