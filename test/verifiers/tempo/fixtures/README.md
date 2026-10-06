# Tempo verifier fixtures

Real data from Tempo mainnet (Presto, chain id 4217), fetched over the public RPC and converted to
the encodings the verifier consumes.

| File | Content |
|---|---|
| `presto-tip.json` | the latest finalized block at generation time: Tempo header RLP, the certificate cut into proposal / compressed signature / seed, the signature in EIP-2537 uncompressed form, and the key that signed the block in both encodings |
| `presto-boundary.json` | the last block of the previous epoch (height `e·21600 − 1`), whose `extraData` carries the `OnchainDkgOutcome` for epoch `e`. The same fields as the tip, plus `nextKeyCompressed` / `nextKeyUncompressed`: the key that the block announces |
| `constants.json` | the G1 and G2 generators and the negated G2 generator in EIP-2537 form |
