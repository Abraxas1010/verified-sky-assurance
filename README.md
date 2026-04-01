<img src="assets/Apoth3osis.webp" alt="Apoth3osis — Formal Mathematics and Verified Software" width="140"/>

<sub><strong>Our tech stack is ontological:</strong><br>
<strong>Hardware — Physics</strong><br>
<strong>Software — Mathematics</strong><br><br>
<strong>Our engineering workflow is simple:</strong> discover, build, grow, learn & teach</sub>

---

[![License: Apoth3osis License Stack v1](https://img.shields.io/badge/License-Apoth3osis%20License%20Stack%20v1-blue.svg)](LICENSE.md)

# Verified SKY Assurance

Separate assurance lane for cryptographic attestation, STARK/ZK-style receipts, and on-chain registry workflows built on top of SKY proof bundles.

## What This Repo Ships

- attestation inspection and verification tooling
- Solidity verifier and registry contracts
- local Foundry harness with positive and tamper-path coverage for the Solidity lane
- security-model and limitations documentation
- local verification scripts for assurance-specific artifacts

## What This Repo Does Not Replace

- `verified-sky-checker`: the deployed customer-facing service and delivery packager
- `sky-proof-checker`: the minimal independent replay verifier

## Which Repo Does What?

- `verified-sky-checker`: Google Cloud service deployment and delivery packaging
- `sky-proof-checker`: customer and auditor replay
- `verified-sky-assurance`: separate STARK/ZK and on-chain assurance lane

## Applied Team Guidance

See:

- `docs/google_cloud_assurance_workflow.md`
- `docs/applied_team_handoff.md`
- `docs/production_team_handoff.md`
- `docs/security_model.md`
- `docs/onchain_limitations.md`

## Local Verification

```bash
./scripts/verify_all.sh
```

This gate now covers:

- Python attestation verification regressions
- multi-case positive attestation corpus checks
- Foundry contract tests for positive, tamper, duplicate-registration, and batch paths
- gas budget checks for the main on-chain verification paths

The Solidity lane is explicit and local-only:

```bash
forge test
```

## Container Quick Start

```bash
docker build -t verified-sky-assurance .
docker run --rm verified-sky-assurance
```

## License

[Apoth3osis License Stack v1](LICENSE.md)
