# Tempo verifier fixtures

Real data from Tempo mainnet (Presto, chain id 4217), fetched over the public RPC and converted to
the encodings the verifier consumes.

| File | Content |
|---|---|
| `presto-tip.json` | the latest finalized block at generation time: Tempo header RLP, the certificate cut into proposal / compressed signature / seed, the signature in EIP-2537 uncompressed form, and the key that signed the block in both encodings |
| `presto-boundary.json` | the last block of the previous epoch (height `e·21600 − 1`), whose `extraData` carries the `OnchainDkgOutcome` for epoch `e`. The same fields as the tip, plus `nextKeyCompressed` / `nextKeyUncompressed`: the key that the block announces |
| `constants.json` | the G1 and G2 generators and the negated G2 generator in EIP-2537 form |
| `localnet.json` | from the 3-validator network in `tools/tempo-localnet`: a real `ClprService` channel's `eth_getProof` output, the certified header it lives under, a config block certified by the pre-rotation key, and the epoch-boundary block that carries the post-DKG key. Consumed by `TempoLocalnet.t.sol`; regenerate with `tools/tempo-localnet/capture-fixtures.js` |

Regenerate with:

```bash
node test/verifiers/tempo/fixtures/generate.js
```

The script needs network access to `rpc.presto.tempo.xyz` and uses `@noble/curves`. It reads each
signing key from the chain: the key of epoch `E` is the one announced in the `extraData` of block
`E·21600 − 1`. It checks every header hash and certificate before it writes anything. To write
somewhere else, pass a directory as the first argument. The tests do not depend on which block was
captured, and they hold across a full DKG, so regenerating is safe at any time. The public RPC keeps
certificates for roughly the last million heights, so an older capture cannot be fetched again.
