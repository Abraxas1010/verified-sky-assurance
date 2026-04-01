# Applied Team Handoff

## Repo Roles

- `verified-sky-checker`: production delivery API
- `sky-proof-checker`: independent customer replay
- `verified-sky-assurance`: optional cryptographic and on-chain assurance

## Decision Rule

Do not deploy this repo by default.

Add it only when the statement of work includes one of these requirements:

- cryptographic attestation beyond plain replay
- externally verified assurance receipts
- on-chain registry or verifier integration

## Workflow

1. Produce and verify the base SKY bundle through `verified-sky-checker`.
2. Confirm the customer replay path with `sky-proof-checker`.
3. If required, create or verify the assurance artifact in this repo.
4. Keep the assurance artifact clearly labeled as an extra assurance surface, not the base proof checker.
