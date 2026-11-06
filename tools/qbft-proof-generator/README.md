# QBFT Besu proof generator

Generates the real Besu QBFT fixtures that `test/integration/IntegrationQBFT.t.sol` consumes,
including a real 3 → 2 validator-set rotation. The
fixtures are for the **header-mode** verifier (`QbftHeaderModeVerifier`, reached through
`QBFTVerifier`): the validator set is read from each header's `extraData`. See
`src/verifiers/evm/qbft/qbft-header-mode.md` for the formats.

The outputs land in `test/verifiers/evm/qbft/fixtures/` (gitignored). Regenerate them; never commit them.

## Re-generating the fixture

```bash
cd tools/qbft-proof-generator
node generate-fixture.js
```

Prerequisites:
- Docker (for the 3-node Besu QBFT cluster)
- Node.js 22+
- Foundry (`forge`, `cast`)

### What the script does

`generate-fixture.js`:
1. Starts a 3-validator QBFT Besu cluster via docker-compose. Every header lists the 3 validators.
2. **Bootstraps `configProof.hex`** from an early block so the Forge script can proceed
   (service address and codeHash are zeros at this point).
3. Deploys `ClprService` + completes a channel + sends one message via `QbftFixtureSetup.s.sol`.
4. Calls `eth_getProof` for the channel slots and fetches the raw header of the bundle block.
5. Writes `bundlePayload.hex`: `RLP([header, [validators, []], accountProof, storageProof, bundleContent])`.
   Field 1 is the trusted set (the validators the header lists) and an empty hop list.
6. Writes `trustAnchor.hex`: the 128-byte anchor `verifyConfig` will produce
   (`abi.encode(uint8 0, bytes32 setCommitment, bytes32 codeHash, uint64 anchorBlock)`).
   The anchor block is the block **before** the bundle block, so the bundle block is after the anchor.
7. Overwrites `configProof.hex` with the final 6-field proof: real service address, real codeHash,
   descriptor `[0, codeHash]`, header of the anchor block.
8. Writes `channelContext.hex`, `serviceAddress.hex`, `metadata.json`, `debug-proof-data.json`.
9. **Rotates the validator set** and writes `bundlePayload.rotation.hex`. It casts
   `qbft_proposeValidatorVote(<validator #2>, false)` on node0 and node1 (a majority of the three),
   waits until the chain head lists two validators, and walks back to the **change block**: the first
   header whose `validators[]` lists the new set. It then proves the
   **same** channel state two blocks later, at a block sealed by the two remaining validators alone,
   and packs `RLP([header, [threeValidators, [changeBlockHeader]], accountProof, storageProof,
   bundleContent])`. The trusted set is still the anchored 3-member set; the hop moves the verifier
   to the 2-member set. `IntegrationQBFT.t.sol::test_fullLifecycle_withRotation` submits it from a
   fresh channel and asserts the anchor rotated. `metadata.json` gains a `rotation` section.
10. Stops the Besu cluster.

### Bootstrap / final configProof cycle

There is an intentional dependency cycle: the Forge script needs a valid `configProof.hex`
(because it calls `completeChannel` → `verifyConfig`), but the final `configProof.hex` needs the
service address and codeHash that only exist after the Forge script deploys the contracts. The
script breaks this cycle by:

1. Writing a **bootstrap** `configProof.hex` with zeros for the service address and codeHash
   (valid for `verifyConfig`, whose seal check only needs the header).
2. Running the Forge script against that bootstrap file.
3. Overwriting `configProof.hex` with the **final** version.
