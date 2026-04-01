# On-Chain Limitations

- gas cost depends on proof size
- contract correctness must be audited independently
- cryptographic soundness is a second trust layer beyond the minimal SKY reducer
- the local harness now checks transcript-derived query positions, FRI folding,
  and final-constant closure for the current proof shape, but broader proof
  families still need additional fixture coverage

Do not market the on-chain path as equivalent to the base verifier's trust profile.
