# Production Team Handoff

## Repo Role

`verified-sky-assurance` is the optional stronger-assurance lane for the SKY stack.

Its job is to add:

- cryptographic attestation verification
- Solidity verifier and registry logic
- local evidence for on-chain and STARK-style assurance paths

This repo is not the default customer path. It is the extra assurance surface when a product or contract explicitly requires more than replayable bundle checking.

## Product Fit

Use this repo when the product promise is:

- "the delivered proof artifact has a cryptographic attestation"
- "the verifier logic can be checked on-chain"
- "the registry records only bundles whose assurance proof has been accepted"

Good product uses:

- smart contract certification and registry workflows
- premium assurance tiers for enterprise or regulated buyers
- optional ZK/STARK-backed verification lanes

Do not use this repo as:

- the default customer verifier
- the main delivery API
- a substitute for the minimal replay trust profile

## How Production Teams Work With It

Recommended product flow:

1. Produce and verify the base bundle through `verified-sky-checker`.
2. Confirm independent replay through `sky-proof-checker`.
3. Add this repo only if the engagement requires cryptographic or on-chain assurance.
4. Keep the assurance lane isolated operationally from the default delivery lane.

Operational guidance:

- treat attestation generation/verification as a separate controlled workflow
- keep contract publication and registry operations under separate operational controls
- do not market this lane as equivalent to the minimal replay verifier’s trust profile

## What Has Been Tested

Current local release evidence covers:

- Python attestation verification regressions
- positive attestation verification across multiple reducer shapes
- malformed attestation rejection for:
  - empty proof payloads
  - wrong bundle binding
  - wrong trace length
  - low security-bit claims
  - wrong obligation-count claims
- Foundry positive/tamper-path contract tests
- duplicate-registration rejection
- batch verification with mixed valid/invalid proofs
- gas budget ceilings for the main positive, tamper, binding, and batch paths

Primary verification command:

```bash
./scripts/verify_all.sh
```

Direct Solidity verification:

```bash
forge test
python3 scripts/check_gas_budgets.py
```

## Release Gate

Before any production promotion of the assurance lane:

```bash
./scripts/verify_all.sh
```

Promotion should be blocked if any of the following fail:

- Python assurance tests
- Foundry positive/tamper/batch tests
- gas budget checks
- positive fixture regeneration

## Product Boundary

- customer-facing API: `verified-sky-checker`
- independent replay verifier: `sky-proof-checker`
- assurance/on-chain lane: `verified-sky-assurance`

This repo is the optional higher-assurance tier, not the base product promise.
