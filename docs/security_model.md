# Security Model

## Base Assumptions

This assurance lane adds assumptions beyond the base SKY verifier:

1. the attestation construction is sound
2. the attestation verifier implementation matches the attestation format
3. the Solidity verifier and registry contracts implement the intended checks

## Current Status

- attestation code: reference implementation
- contract surfaces: reference implementation
- production posture: requires independent assurance review before buyer claims are upgraded
