# Tempo localnet: real finality, real key rotation

A 3-validator Tempo network in Docker, built only from the published images (`ghcr.io/tempoxyz/tempo`,
`ghcr.io/tempoxyz/tempo-xtask`), pinned by digest to the build that produced the committed fixtures; no
Rust toolchain needed. It is used to produce
`test/verifiers/tempo/fixtures/localnet.json`, which `test/verifiers/tempo/TempoLocalnet.t.sol`
feeds to `TempoVerifier`: a real `ClprService` channel proven with real `eth_getProof` output under
real finalization certificates, across a real group-key rotation.

## Prerequisites

Docker (compose v2), Node 24 with the repository's `node_modules`, Foundry (`cast`, `forge`). About
2 GB of RAM for the three nodes.

## Procedure

1. **Generate the network** (genesis, validator keys, DKG shares; epoch length 100 blocks):

   ```bash
   tools/tempo-localnet/generate-localnet.sh
   ```

2. **Start it** and wait for blocks (about 30 s):

   ```bash
   cd tools/tempo-localnet && docker compose up -d
   cast block-number --rpc-url http://127.0.0.1:18545
   ```

   Nodes listen on `127.0.0.1:18545`, `18546`, `18547`. `consensus_getFinalization` works on all
   three. The compose file passes `--rpc.eth-proof-window=1000000` so `eth_getProof` answers for
   any recent block; reth's default answers only for the head.

3. **Deploy a ClprService** with the repository's deploy CLI (fees are paid in the localnet's
   pathUSD automatically; the first mnemonic account is funded):

   ```bash
   PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
     npx tsx script/deploy/cli.ts all --rpc-url http://127.0.0.1:18545
   ```

4. **Initialize the service and complete a channel** on it (through the `E2EVerifier` double):

   ```bash
   PRIVATE_KEY=0xac09…ff80 CLPR_SERVICE=<address from step 3> \
     npx tsx tools/tempo-localnet/setup-channel.ts http://127.0.0.1:18545
   ```

   It prints `FIXTURE_OUT::CHANNEL_ID`. Add `SKIP_INIT=1` when re-running against an already
   initialized service.

5. **Schedule a full DKG.** The validator-config owner is the first mnemonic account. A rotation
   scheduled for epoch `E` makes the ceremony *during* epoch `E` a full DKG, so the key changes for
   epoch `E+1`; the last block of epoch `E` carries the new key in its `extraData`. Pick `E` at
   least two epochs ahead of the current one:

   ```bash
   cast send 0xCCCCCCCC00000000000000000000000000000001 "setNetworkIdentityRotationEpoch(uint64)" <E> \
     --rpc-url http://127.0.0.1:18545 --private-key 0xac09…ff80
   ```

   Then wait until the chain is past block `(E+1)·100`. Verify with
   `cast call 0xCCCC…0001 "getNextNetworkIdentityRotationEpoch()(uint64)"`.

6. **Capture the fixtures**, passing the first epoch signed by the new key (`E+1`):

   ```bash
   node tools/tempo-localnet/capture-fixtures.js <service> <channelId> <E+1>
   ```

   The script records: a config block from the middle of epoch `E` with its certificate (old key),
   the boundary block `(E+1)·100 − 1` with its certificate (the rotation), the head block with its
   certificate and the channel's `eth_getProof` (current), and the block before it (steady-state
   anchor). It aborts if the boundary does not actually change the key.

7. **Run the test:**

   ```bash
   FOUNDRY_PROFILE=test forge test --match-contract TempoLocalnetTest -vv
   ```

8. **Stop the network:** `cd tools/tempo-localnet && docker compose down`. The generated
   `localnet/` directory is git-ignored; regenerate it for a fresh chain.

## What the fixture proves

| Test | Real-chain claim |
|---|---|
| `test_localnet_configUnderOldKey` | the pre-rotation key finalizes a real block; the anchor pins it |
| `test_localnet_bundleAcrossRotation` | one rotation (the boundary block, certified by the old key, naming the new key) carries the verifier across the full DKG and every reshare after it; the real channel slots decode to the real channel state; the anchor rotates |
| `test_localnet_steadyStateUnderNewKey` | a bundle under the post-rotation key with no rotations |
| `test_localnet_missingRotationIsRejected` | the old key does not verify a post-rotation block |
| `test_localnet_oldKeyCannotSignNewEpoch` | same, with a post-rotation anchor height |
| `test_localnet_boundaryCertifiedByOldKeyOnly` | the two keys differ and both compress to what the chain committed |

## Notes

- The genesis initializes **ValidatorConfigV2** at `0xCCCCCCCC…0001`; the V1 precompile at
  `…0000` reports a zero owner and rejects the V1 function names.
- Certificates on this network are 130 bytes (short varints), on mainnet 134; the verifier never
  assumes a length.
- `tools/tempo-localnet/TempoLocalnetChannel.s.sol` does the same as `setup-channel.ts` as a Forge
  script, for environments that prefer `forge script --broadcast`.
