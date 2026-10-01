# CLPR E2E

End-to-end harness that spins up two local EVM chains, deploys `ClprService`
on each, and drives cross-chain messaging tests. One test code path, three
node kinds: **Anvil** (fast, no Docker), **Besu** (real client, QBFT devnet via
Docker Compose + Testcontainers), and **Solo** ([Hiero](https://solo.hiero.org/)
one-shot + JSON-RPC relay).

Chain A (chainId 1337) and chain B (chainId 1338) are independent: set
`CLPR_BACKEND` to a single kind (`besu`) or a mixed spec (`besu:solo` =
Besu on A, Solo on B). Infrastructure startup is side-aware via `infra.ts`.

The harness lives in this `test/e2e/` directory alongside the Foundry tests.
**Dependencies and configuration are at the repo root** (`package.json`,
`tsconfig.json`, `vitest.config.ts`). One `npm install` from the root
brings everything online.

Foundry (`forge test`) and Vitest (`npm run test:e2e`) coexist without
interfering: Foundry only globs `*.sol`; Vitest only globs
`test/e2e/tests/**/*.spec.ts`.

## Prerequisites

| Backend | Required | Install |
|---|---|---|
| `anvil` | Foundry | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| `besu`  | Docker  | https://docs.docker.com/get-docker/ |
| `solo`  | Docker, [Solo CLI](https://solo.hiero.org/docs/simple-solo-setup/quickstart/) | `npm install` pulls `@hiero-ledger/solo`; Solo manages Kind |

Node 24+ (Active LTS) for Vitest and deploy. Solo lifecycle scripts use `node --experimental-strip-types`.

## First run

```bash
# From the repo root
forge build                  # produces out/*.json artifacts the e2e suite consumes
npm install
npm run test:e2e             # default = anvil, ~10s, no Docker
```

For Besu (tests can start containers inline, or reuse a pre-started stack):

```bash
npm run test:e2e:besu        # ~30s first run, ~15s thereafter (image cached)

# Optional: keep Besu running between runs (fixed ports 18545 / 18546)
npm run e2e:up:besu
npm run test:e2e:besu        # BesuNode reads test/e2e/backend/.besu-state/
npm run e2e:down:besu
```

### Solo (two Hiero networks, EVM relay)

Networks are **not** started by Vitest. Solo owns Kind, port-forwards, and accounts.

```bash
npm run e2e:up:solo          # infra.ts: both Solo sides (or e2e:solo:up for solo/cli.ts directly)
npm run e2e:solo:status      # check JSON-RPC relays
npm run test:e2e:solo        # same specs as anvil/besu
npm run e2e:down:solo        # tear down both sides
```

Each side gets its **own Kind cluster** (`clpr-solo-a-cluster` / `clpr-solo-b-cluster`,
contexts `kind-clpr-solo-a-cluster` / `kind-clpr-solo-b-cluster`), Kubernetes namespace, and **fixed** JSON-RPC relay
port (default `37546` / `37547`). Deploy uses Solo **Falcon** with a single
[`falcon.yaml`](backend/solo/falcon/falcon.yaml) template (chain id substituted per side).
`eth_call` / `block.chainid` come from **mirror-web3** (`mirror-values.yaml`), not a post-deploy JVM patch.

**Multinode TSS (default):** each side deploys **3 consensus nodes** with real TSS-BLS block signing on consensus
platform **v0.73.0**. TSS flags are in
[`network-application-tss.properties`](backend/solo/falcon/network-application-tss.properties).
Set `CLPR_SOLO_CONSENSUS_NODES=1` for a lighter single-node cluster.

**Block node (default on):** Falcon includes a block node (`ONE_SHOT_WITH_BLOCK_NODE=true`) for
HIP-1081 `ProofService` state proofs. Requires **≥16 GB Docker RAM** per side with block node enabled.
Disable with `CLPR_SOLO_BLOCK_NODE=false` (lighter, but no `getStateProof` API).

After `e2e:solo:up`, the harness port-forwards relay, mirror REST (`39081`/`39082`), and block node gRPC
(`39100`/`39101`) into `.solo-state/*.url` files.

See [Solo Falcon deployment](https://solo.hiero.org/docs/advanced-solo-setup/network-deployments/falcon-deployment/).

### Mixed backends (Besu|Anvil ↔ Solo) — cross-verifier E2E

Cross-chain specs deploy **EVM `ClprService` on both sides** (not native `0x16e`). Proof
construction is **asymmetric**:

| Direction | Proof built on | Verifier on receiver |
|-----------|----------------|----------------------|
| Besu → Solo | Besu (`eth_getProof` + `debug_getRawHeader`) | `QBFTVerifier` |
| Solo → Besu | Solo EVM storage + mirror SlotKey paths | `HieroVerifier` stack |

```bash
# Mixed Besu + Solo — one Besu + one Solo (`besu-a` + `solo-b`); order is canonical
npm run e2e:up:besu:solo    # same as e2e:up:solo:besu
npm run test:e2e:besu:solo  # cross-verifier roundtrip only (A=besu, B=solo)
npm run test:e2e:solo:besu  # alias — `solo:besu` normalizes to the same layout
npm run e2e:down:besu:solo
```

`CLPR_BACKEND=besu:solo` and `CLPR_BACKEND=solo:besu` are equivalent: mixed specs sort
alphabetically by kind (**avalanche < anvil < besu < solo**), so both resolve to A=besu, B=solo.
The roundtrip spec runs Besu→Solo and (when unblocked) Solo→Besu ferries in one suite.

**Verifier env (not on `Backend`):** `CLPR_QBFT_VALIDATOR` (Besu genesis validator #0),
`CLPR_SOLO_LEDGER_ID` (or `test/verifiers/hiero/fixtures/trustAnchor.bin`) for `HieroVerifier` on Besu.
Mirror REST is used for EVM address → contract id lookup only.
`buildHieroProof` calls `ProofService.getStateProof` per `SlotKey` (HIP-1081). On block node
v0.33.x that RPC is not implemented — `getStateProof` throws; B→A stays skipped until it ships.

**Anvil + Solo (`npm run test:e2e:anvil:solo`, `CLPR_BACKEND=anvil:solo`).** Same spec with anvil
on A (harness-started; `CLPR_ANVIL_PORT_A` overrides port 8545) and `E2EVerifier` stub proofs A→B.
For B→A it authenticates the Solo reply without `ProofService`
([`relay/hieroBlockProof.ts`](relay/hieroBlockProof.ts)): it finds the `state_changes` block item
that writes the reply's running hash, recomputes the block root from the block's items
(consensus node v0.74 `BlockStreamManagerImpl.combine`), checks it against the next block's
`BlockFooter.previous_block_root_hash`, then on anvil derives the root from a `block_item_leaf`
`StateProof` with the production `ClprStateProof`/`ClprMerkleProof`, and verifies Solo's real hinTS
aggregate signature over it (a tampered root fails). The production `TSSVerifier` then stops at
`ClprHieroWrapsProofRequired`: Solo block proofs carry the 192-byte Schnorr genesis
address-book proof (2920-byte signature), not WRAPS (3432 bytes). A full `HieroVerifier` delivery
also needs native `ClprChannel`/`ClprMessageValue` state items, which an EVM-deployed
`ClprService` does not produce.

**Storage slot derivation** (from `storage-layout.json`):

| Data | Root slot | Derivation |
|------|-----------|------------|
| `_messageQueues` | **1** | `keccak256(abi.encode(messageId, keccak256(abi.encode(channelId, 1))))` |
| `_channels` | **17** | `keccak256(abi.encode(channelId, 17))` + struct field offsets (+1,+2,+4,+5) |

Homogenous `anvil` / `besu` specs still use `E2EVerifier` (stub proofs). See
`test/e2e/tests/solo-cross-roundtrip.spec.ts` for real cross-verifier roundtrip.

### Mixed backends (legacy note)

Cross-chain specs are the same; only the **per-side** RPC client differs. Mixed runs
previously used `E2EVerifier` on both chains — that path remains for `anvil:besu` etc.

```bash
# Mixed Besu + Solo: besu-a (chain A) + solo-b (chain B)
npm run e2e:up:besu:solo
npm run test:e2e:besu:solo
npm run e2e:down:besu:solo
```

Other examples: `CLPR_BACKEND=anvil:besu`, `solo:besu`. Same pattern:

```bash
node --experimental-strip-types test/e2e/backend/infra.ts up anvil:besu
CLPR_BACKEND=anvil:besu npm run test:e2e
```

Anvil sides need no `e2e:up` step (Vitest spawns `anvil` inline).

## Daily commands (all from repo root)

| Command | What it does |
|---|---|
| `npm run test:e2e`        | Default — Anvil. Fast inner loop. |
| `npm run test:e2e:anvil`  | Explicit Anvil run. |
| `npm run test:e2e:besu`   | Both chains Besu (inline Testcontainers or pre-started stack). |
| `npm run test:e2e:solo`   | Both chains Solo (`e2e:up:solo` or `e2e:solo:up` first). Sequential specs (`vitest.solo.config.ts`). |
| `npm run test:e2e:besu:solo` | Cross-verifier roundtrip (`solo-cross-roundtrip.spec.ts` only). |
| `npm run test:e2e:solo:besu` | Alias — same spec (`solo:besu` → canonical `besu:solo`). |
| `npm run test:e2e:all`    | Anvil then Besu — mirrors CI. |
| `npm run e2e:up`          | `infra.ts up` with default spec `anvil` (no-op for nodes). |
| `npm run e2e:down`        | `infra.ts down` with default spec `anvil`. |
| `npm run e2e:up:besu`     | Docker Compose: `besu-a` + `besu-b` on ports 18545 / 18546; writes `.besu-state/`. |
| `npm run e2e:down:besu`   | Stop Besu stack and clear `.besu-state/`. |
| `npm run e2e:besu:status` | `docker compose ps` for the Besu stack. |
| `npm run e2e:up:solo`     | Start Solo A + B via `infra.ts` (fast-path if relays already up). |
| `npm run e2e:down:solo`   | Tear down Solo A + B via `infra.ts`. |
| `npm run e2e:up:besu:solo`| Start mixed stack: `besu-a` + `solo-b`. Same as `e2e:up:solo:besu`. |
| `npm run e2e:down:besu:solo` | Tear down mixed stack. Same as `e2e:down:solo:besu`. |
| `npm run e2e:solo:up`     | Solo lifecycle (both sides) via `solo/cli.ts`. |
| `npm run e2e:solo:down`   | Solo destroy (both sides). |
| `npm run e2e:solo:status` | Probe Solo relays and chain IDs. |
| `npm run test:e2e:watch`  | Vitest watch mode (Anvil only — Besu too slow). |

### Useful env vars

| Var | Effect |
|---|---|
| `CLPR_BACKEND=anvil\|besu\|solo` | Same kind on A and B. |
| `CLPR_BACKEND=a:b` | Mixed backends, e.g. `besu:solo`, `anvil:besu`. Specs sort alphabetically by kind (A = earlier, B = later). |
| `SOLO_RPC_A`, `SOLO_RPC_B` | Override relay URLs (set automatically after `e2e:solo:up`). |
| `CLPR_QBFT_VALIDATOR` | QBFT validator address for proof building (default: Besu genesis account #0). |
| `CLPR_SOLO_LEDGER_ID` | Hiero ledger id bytes for `HieroVerifier` / trust anchors. |
| `CLPR_SOLO_FUNDED_KEY` | Use this key as the Solo **funder** (not the per-suite deployer). |
| `CLPR_SOLO_RELAY_PORT_A/B` | Local relay ports (default `37546` / `37547`). |
| `CLPR_SOLO_MIRROR_PORT_A/B` | Local mirror REST ports (default `39081` / `39082`). |
| `CLPR_SOLO_BLOCK_NODE_PORT_A/B` | Local block node gRPC ports (default `39100` / `39101`). |
| `CLPR_SOLO_CONSENSUS_NODES` | Consensus nodes per side (default `3`; set `1` for lighter deploy). |
| `CLPR_SOLO_BLOCK_NODE` | Set `false` to skip block node (no `ProofService`). Default on. |
| `CLPR_SOLO_NAMESPACE_A/B` | K8s namespace per side (default `clpr-solo-a` / `clpr-solo-b`). Kind cluster `{ns}-cluster`, kubectl context `kind-{ns}-cluster`. |
| `CLPR_KEEP_NODES=1`        | Skip teardown — leave nodes/containers running. Inspect with `cast`. |
| `CLPR_LOG=trace`           | Forward driver stdout/stderr to the test process. |

Each spec file provisions its own deployer via `provisionE2ESuite()` (deterministic key per suite id: `smoke`, `channel`, `connector`, `roundtrip`), funded per side from `backend.fundedKeyA()` / `fundedKeyB()` (Anvil/Besu account #0 or Solo ecdsa-alias for that side). Deploy uses that suite key plus **`protocolVersion`** / CAIP **`chainId`** (`backend.caipA()` / `caipB()`).

### Run one file / one test

```bash
# One file
npm run test:e2e -- test/e2e/tests/smoke.spec.ts

# Tests matching a name
npm run test:e2e -- -t "kill-switch"
```

## Ethereum ↔ Hiero (real proofs)

### Ethereum → Hiero: `EthMainnetVerifier` on a Hiero network

`script/gas/eth-verifier-hiero.ts` deploys `EthMainnetVerifier` through a Hiero JSON-RPC relay
and submits `verifyBundle` for the recorded live Sepolia bundle
(`test/e2e/fixtures/sepolia-live/capture.json`, same inputs as `npm run test:e2e:eth-live`) as a
real `EthereumTransaction`. It reports the gas and HBAR that consensus charged (receipt + mirror
node `charged_tx_fee`), and whether the relay sent the large calldata as a jumbo transaction or
through HFS (`FileCreate`/`FileAppend` paid by the relay operator just before the call).

```bash
forge build

# Local Solo side B (relay :37547, mirror :39082). Funds a throwaway key from the Solo funder.
npm run gas:eth-verifier:solo

# Hedera testnet (chain 296). Reads CLPR_TESTNET_PRIVATE_KEY, HEDERA_TESTNET_RPC_URL and
# HEDERA_TESTNET_MIRROR_URL from ~/clpr/.env (or --env <file>). Spends testnet HBAR and writes
# test/e2e/fixtures/sepolia-live/hiero-gas-hedera-testnet.json.
npm run gas:eth-verifier:testnet                       # deploy + verify (~5.6 HBAR)
npm run gas:eth-verifier:testnet -- --verifier 0x92646d66a66e93411d6f679f4b4befebdb3371bd  # verify only (~1.6 HBAR)
```

Measured 2026-10-01 (bundle: Sepolia slot 11254195, 486/512 signers, 18 587 B proof, 19 140 B calldata):

| Network | Step | Gas (receipt = consumed) | Fee charged | Hiero tx |
|---|---|---|---|---|
| anvil (reference) | `verifyBundle` | 1 645 052 (`eth_estimateGas`) | — | — |
| Hedera testnet, HAPI 0.77.2 | deploy (19 364 B init code) | 4 213 415 | 4.0449 HBAR | 1 jumbo `ETHEREUMTRANSACTION`, no HFS |
| Hedera testnet, HAPI 0.77.2 | `verifyBundle` (succeeds, run twice) | 1 645 052 | 1.5792 HBAR | 1 jumbo `ETHEREUMTRANSACTION`, no HFS |
| Solo, consensus v0.74 | deploy | 4 213 415 | 2.9915 HBAR | 1 jumbo `ETHEREUMTRANSACTION`, no HFS |
| Solo, consensus v0.74 | `verifyBundle` | reverts `BlsPrecompileCallFailed` | — | — |

- Gas on Hedera testnet equals the anvil figure exactly. Testnet charged 96 tinybar/gas
  (fee = gas × price); the Solo fee schedule is 71 tinybar/gas. Hiero charges at least 80% of
  the gas limit, so the script signs `estimate × 1.15`.
- Solo cannot verify the bundle: consensus v0.74 runs EVM `v0.67`, which has no EIP-2537
  BLS12-381 precompiles (`eth_call` to `0x0b` returns empty data; on testnet it returns the
  point at infinity). The script probes this and reports `eip2537`.
- Size limits. A standard Hiero transaction is capped at 6 144 B
  (`hedera.transaction.maxBytes`). Larger `EthereumTransaction`s go through as HIP-1086 jumbo
  transactions: consensus allows 133 120 B per transaction and 131 072 B of calldata
  (`jumboTransactions.maxTxnSize`, `jumboTransactions.ethereumMaxCallDataSize`). Relay 0.77
  mirrors this in precheck (`SEND_RAW_TRANSACTION_SIZE_LIMIT` 133 120, `CALL_DATA_SIZE_LIMIT`
  131 072) and only falls back to HFS when `JUMBO_TX_ENABLED=false`. Both the local relay and
  hashio reject 131 100 B of calldata with `Oversized data: call data size 131100, call data size
  limit 131072` before submission. Hashio's intrinsic-gas precheck prices non-zero calldata bytes
  at 40 gas (the EIP-7623 floor); for this bundle the floor (≈ 750 k) is below the execution cost,
  so it does not bind.

### Hiero → Ethereum: status on the local Solo network

`HieroVerifier` needs, per bundle, a `StateProof` whose `signed_block_proof` is a WRAPS-settled
hinTS signature (3 432 B; `TSSVerifier` rejects the 2 920 B genesis-Schnorr form with
`ClprHieroWrapsProofRequired`) and whose state-item leaves are native CLPR state values
(`StateValue` tags 482 channel, 498 message, 514 manifest). The Solo network started by
`npm run e2e:up -- anvil:solo` does not provide that yet:

- Block node `0.38.0` has no `ProofService` (`getStateProof` returns gRPC status 5); the plugin
  list reported by `serverStatusDetail` has no proof plugin.
- Consensus nodes run with `tss.wrapsEnabled=false`, so every block proof carries a genesis
  Schnorr signature (2 920 B).
- `buildHieroProof.ts` requests `SlotKey` (EVM contract storage) proofs for a `ClprService`
  deployed as a contract on Solo. `ClprStateProof` skips such leaves as unknown tags, so even
  with a proof service the bundle would fail with `StateProofMissingChannel`. A real
  Hiero → Ethereum leg needs the source to be the native Hiero CLPR service.

The recorded WRAPS-signed fixture in `test/verifiers/hiero/fixtures/` (from a localnet with the
native CLPR service) is what `HieroVerifier` is currently tested against (`forge test --match-contract HieroVerifierTest`).
What the live Solo network can already prove on anvil (Solo's hinTS aggregate signature over a
block-item root) is covered by `npm run test:e2e:anvil:solo` (see the mixed-backends section above).

## What's deployed per chain

Deploys use **viem** via `script/deploy/` (same code path as `bin/deploy.sh`). E2E tests call `test/e2e/deploy/deploy.ts`, which wraps the shared deploy module:

1. Logic modules — `ChannelLogic`, `MessagingLogic`, `BundleLogic`, `ConnectorLogic`, `AdminLogic`, `BundleDecodeHelper` (separate deploys keep `ClprService` initcode under the EIP-3860 49KB cap).
2. `ClprService` — router; constructor receives deployer as `initialOwner`, `protocolVersion`, CAIP `chainId` string (e.g. `eip155:1337`), and the module addresses above.
3. E2E-only contracts — `E2EVerifier`, `E2EApplication`, `MockClprConnector`, `BundleEncoderHelper`.

Bytecode comes from `out/` after `forge build`. `wireConfig` applies e2e-specific ledger + economic defaults after deploy.

### Single-chain operator deploy (no Vitest)

From the repo root, against one RPC:

Operators: `bin/deploy.sh all --rpc <url>` or `npm run deploy -- all --rpc-url <url>` (see repo `README.md`).

`wireConfig` writes default throttles + economic config. `registerEndpoint`
bonds the relay's address as an authorized bundle submitter.

## CI

`.github/workflows/602-flow-e2e-tests.yaml`:

- **`e2e / anvil`** — runs on every PR and push. Must pass.
- **`e2e / besu`** — runs on push to `main`, nightly cron, or PRs labeled
  `run-besu`. Catches real-client divergence.

Both jobs run the *same* test files via `CLPR_BACKEND` switching.

## Directory map

```
clpr-smart-contracts/             ← repo root (Foundry + Node configs here)
├── package.json                   npm scripts + deps (vitest, viem, testcontainers)
├── tsconfig.json
├── vitest.config.ts               points at test/e2e/tests/**/*.spec.ts
├── foundry.toml                   (unchanged)
├── src/                           Solidity sources (unchanged)
└── test/                          Foundry .t.sol + the TS E2E harness
    ├── *.t.sol                    Foundry tests (forge test)
    ├── mocks/, helpers/           Foundry test fixtures
    └── e2e/                       TypeScript E2E harness
        ├── README.md              this file
        ├── backend/
        │   ├── Backend.ts          interface + `parseBackendSpec()`
        │   ├── ChainNode.ts        single-chain interface
        │   ├── Driver.ts           pairs two ChainNodes (A/B)
        │   ├── AnvilNode.ts        one `anvil` process
        │   ├── BesuNode.ts         one Besu service (compose / Testcontainers)
        │   ├── SoloNode.ts         one Solo relay (external)
        │   ├── infra.ts            `up` / `down` / `status` per CLPR_BACKEND spec
        │   ├── besu/state.ts       `.besu-state/` RPC URLs after `e2e:up:besu`
        │   ├── docker-compose.yml  besu-a / besu-b (host ports 18545 / 18546)
        │   ├── genesis-a.json      chainId 1337, QBFT, prefunded test account
        │   ├── genesis-b.json      chainId 1338, QBFT, prefunded test account
        │   └── solo/               Kind + Solo one-shot CLI
        ├── deploy/
        │   ├── deploy.ts           e2e wrapper over `script/deploy/` + `deployE2EPair`
        │   └── wire.ts             updateLedger/Economic config, registerEndpoint
        ├── lib/
        │   (artifacts: script/deploy/artifacts.ts — loads forge JSON from out/)
        │   └── clients.ts          viem public + wallet clients per chain
        ├── relay/
        │   └── relay.ts            SKELETON — bundle relay (TODO)
        └── tests/
            ├── smoke.spec.ts       deploy + config + endpoint + kill-switch (green)
            └── roundtrip.spec.ts   SKIPPED — needs bundle encoder (TODO)
```

## Next milestones

The smoke suite is green; the roundtrip suite is the real prize. To finish it:

1. **`test/e2e/relay/encodeBundle.ts`** — TS protobuf encoder for `ClprBundleContent`
   ( `field 1 = ClprQueueMetadata`, `field 2 = repeated ClprMessagePayload`).
   Mirror the on-chain decoder in [`src/libraries/codec/ClprProtobuf.sol`](../../src/libraries/codec/ClprProtobuf.sol).
2. **`test/e2e/lib/deriveIds.ts`** — TS port of `_deriveChannelId` /
   `deriveConnectorId` (keccak-sorted chain IDs, etc.) to produce
   byte-identical IDs on both sides.
3. **`test/e2e/deploy/wireChannel.ts`** — commit-reveal a paired channel on
   both chains using the same pubkey/salt.
4. **`test/e2e/deploy/wireConnector.ts`** — same, for the connector. Funds the
   `MockClprConnector` contract so `payForExecution` can settle.
5. **`test/e2e/relay/relay.ts`** — subscribe to `MessageQueued`, build bundle,
   submit on peer.
6. **`test/e2e/tests/roundtrip.spec.ts`** End2End test.

## Troubleshooting

- **`Artifact for ClprService not found`** — run `forge build` from the repo root.
- **`forge` not found** — install Foundry and ensure `forge` is on `PATH` (e2e shells out to it).
- **Besu fails to start** — check `docker ps`, then `docker compose -f test/e2e/backend/docker-compose.yml ps`. Confirm Docker daemon is running. After `e2e:up:besu`, RPC is `http://127.0.0.1:18545` (A) and `:18546` (B).
- **Besu port in use** — another stack may hold 18545/18546. `npm run e2e:down:besu` or stop the conflicting process.
- **Stale `.besu-state/`** — containers gone but state files remain; BesuNode will fail readiness. Run `npm run e2e:down:besu` or delete `test/e2e/backend/.besu-state/`.
- **Port already in use (Anvil)** — `lsof -i :8545` (or `:8546`) to find the squatter. Ports are set in `test/e2e/backend/AnvilNode.ts` via `index.ts`.
- **CI Besu job is skipped on PR** — that's by design; add the `run-besu` label to your PR to opt in.
- **Solo `Component exists`** — stale deployment; `up` retries after destroy. Full reset: `npm run e2e:solo:down` then `npm run e2e:solo:up`.
- **Only one relay works** / flaky RPC — duplicate `kubectl port-forward` on the same local port. Run `npm run e2e:solo:down` then `npm run e2e:solo:up`. `status` reports `pf:ok` vs `pf:2 port-forwards`.
- **Solo `ctx=…?` in status** — Solo deployment namespace does not match `CLPR_SOLO_NAMESPACE_A/B` (not a wrong Kind context). `npm run e2e:solo:down` then `npm run e2e:solo:up`.
