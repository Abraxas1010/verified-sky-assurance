# Recursive On-Chain Theorem Graph Dossier

This repo persists the on-chain/assurance-side handoff for the `heyting`
project `recursive_succinct_onchain_theorem_graph_20260402`.

## Upstream Source of Truth

- upstream repo: `Abraxas1010/heyting`
- upstream branch: `master`
- upstream persistence commit: `c887299aaa`
- conjecture: `conjectures/recursive_succinct_onchain_theorem_graph_20260402.json`
- proof tree: `Blueprint/proof_trees/recursive_succinct_onchain_theorem_graph_20260402.json`
- claim boundary:
  `Docs/ops/recursive_onchain_claim_boundary_2026-04-02.md`

This dossier is a durable handoff record. The mathematical source of truth
remains the Lean and artifact surfaces in `heyting`.

## What Landed Upstream

The project closed with these published guarantees:

- compile-first submission harvest over the actual checkable declaration
  surface Lean produces, rather than regex-only named-text harvesting
- stronger front door for proof-bearing submissions, including normalized
  top-level `example` and private theorem cases
- recursive receipt fold algebra proved in Lean, including
  `foldPair_preserves_statement`
- Lean-defined public-input verifier model proved, including
  `onChainAccepts_of_envelopeMatchesStatement` and
  `onChainRejects_mutatedDigest`
- stable recursive/on-chain corpus closes 4/4 end to end
- tamper suite rejects 5/5 mutated cases at the appropriate layer
- normalized reflexive equality over already-supported closed data closes
  through the quoted-combinator bridge

## Post-Close Hardening Sync

After the main closeout, upstream published one more hostile-audit remediation
pass tied to `recursive_onchain_production_hardening_20260403`. The specific
operational guarantee added there is:

- stale shared Lean export objects (`*.c.o.export`) now trigger linker-failure
  recovery in the Python lake helper instead of silently leaving the submission
  harvester broken on a dirty checkout
- private declaration text resolution is centralized in
  `HeytingLean.CLI.EnvBootstrap`, with fail-closed handling for ambiguous
  suffix matches
- the recovery path is regression-tested in Python, so this hardening is not
  just an operator note

This does not widen the mathematical claim boundary. It preserves the same
honest theorem/assurance boundary while making the published pipeline more
robust under multi-worktree cache sharing.

## Rust Kernel Sync

Upstream later replaced the deterministic distributed proof-network core with a
Rust kernel while preserving the existing Python command surfaces as thin
compatibility shims. The concrete scope of that change is:

- `verified_proof_root_build.py`, `verified_proof_worker_receipt.py`, and
  `verified_proof_aggregate.py` no longer carry the root/receipt/aggregate
  logic themselves
- the deterministic implementation now lives in
  `projects/recursive_onchain_kernel`
- regression coverage was extended so the existing distributed verification and
  recursive receipt tests continue to pass across the shimmed path

This is an implementation-surface hardening step, not a new mathematical
closure claim. In particular, upstream did **not** publish this step as a
LeanCP-generated Rust artifact; it is a Rust replacement of the prior Python
deterministic core, still governed by the same honest boundary.

## Key Upstream Lean Modules

- `lean/HeytingLean/LoF/LeanKernel/Distributed/RecursiveReceipt.lean`
- `lean/HeytingLean/LoF/LeanKernel/Distributed/RecursiveStatement.lean`
- `lean/HeytingLean/LoF/LeanKernel/Distributed/RecursiveReceiptJson.lean`
- `lean/HeytingLean/LoF/LeanKernel/Distributed/OnChainPublicInput.lean`
- `lean/HeytingLean/LoF/LeanKernel/Distributed/OnChainVerifierModel.lean`
- `lean/HeytingLean/KernelAssurance/GraphRecursiveAssurance.lean`
- `lean/HeytingLean/CLI/RecursiveProofReceiptMain.lean`
- `lean/HeytingLean/CLI/OnChainGraphVerifierMain.lean`
- `lean/HeytingLean/CLI/VerifiedProofSubmissionDeclsMain.lean`
- `lean/HeytingLean/LeanClef/SourceExport/QuotedComb.lean`

## Honest Boundary Preserved Here

This separate repo must preserve the same honest boundary as upstream:

- the current recursive witness backend is deterministic and replayable, not a
  cryptographic SNARK, STARK, or IVC proof
- the on-chain claim is a tiny fail-closed public-input verifier model, not a
  statement of deployed-contract production readiness
- universal source-export closure for arbitrary proof terms is not claimed
- large everyday-style verifier corpora still have throughput/frontier limits

## Why This Repo Carries the Dossier

`verified-sky-assurance` is the correct long-term external persistence surface
for this project because the work's durable value is the assurance-side
statement:

- a recursive receipt is bound to the canonical theorem graph
- a minimal public verifier checks the graph-completeness statement fail-closed
- downstream assurance/contract work can cite this project without reopening
  the entire `heyting` monorepo history

For customer/auditor replay, continue to use `sky-proof-checker`. For the
underlying mathematical proofs and development history, continue to use
`heyting`.
