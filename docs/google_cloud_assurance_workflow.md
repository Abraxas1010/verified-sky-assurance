# Google Cloud Assurance Workflow

This repo is the separate assurance lane for cryptographic attestation and on-chain registration.

## What It Is For

Use `verified-sky-assurance` when the product contract requires more than replayable proof checking, for example:

- STARK or other zero-knowledge style attestation around bundle execution
- signed assurance artifacts
- on-chain verifier or registry integration

## What It Is Not For

Do not use this repo as the default customer verification surface.

The default product path is still:

1. `verified-sky-checker` for service delivery
2. `sky-proof-checker` for independent replay

Only add this repo when the buyer explicitly requires the stronger assurance lane.

## Google Cloud Placement

- run attestation generation or verification as a separate job or isolated service
- keep keys and secrets outside the base service surface
- keep contract publication and registry operations on a separately controlled path

## Plain-Language Boundary

Yes: this is the repo for the ZK/STARK-style assurance lane.

No: it should not be merged back into the minimal replay checker or the default buyer-facing API.
