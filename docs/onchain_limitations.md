# On-Chain Limitations

- gas cost depends on proof size
- contract correctness must be audited independently
- cryptographic soundness is a second trust layer beyond the minimal SKY reducer
- the registry can bind a verified bundle hash to an aggregate receipt hash and
  proof-root hash, but it does not itself re-check shard completeness or closure
- the local harness now checks bundle-hash transcript binding, transcript-derived
  query positions, FRI folding, and final-constant closure for the current proof
  shape, but broader proof families still need additional fixture coverage

Do not market the on-chain path as equivalent to the base verifier's trust profile.
