# Testing Guide

Read this before writing or modifying tests. Pairs with `architecture.md`
(for the system under test) and `bundle-flow.md` (for what bundle tests
exercise).

Foundry / `forge test` for the Solidity suites, Vitest for the end-to-end
harness. All tests live under `test/`.

## Running the suite

```bash
forge test -vvv                                   # the full suite (CI's Test job)
forge test --match-path 'test/logic/**' -vvv      # scope while iterating
forge test --fuzz-runs 10000                      # deeper fuzzing (default 256)
FOUNDRY_PROFILE=test forge build --deny warnings  # what CI builds the test tree with
```

The `test` profile exists because test-only contracts trip the EIP-3860 initcode
(`3860`) and Spurious Dragon runtime-size (`5574`) warnings that are fatal
elsewhere. Invariants run under `[invariant]` (`runs = 256`, `depth = 100`,
`fail_on_revert = false`); fuzz defaults to `runs = 256`. `test/` is excluded
from `forge lint`. File reads are allow-listed via `fs_permissions` in
`foundry.toml` (`./storage-layout.json`, `src/verifiers`, `test/verifiers` and
its fixture directories) — a fixture outside those paths needs an entry there
or `vm.readFile` reverts.

Coverage, as CI's Coverage job runs it (`.github/workflows/600-flow-pull-request-checks.yaml`):

```bash
forge coverage --ir-minimum --no-match-coverage "(test|script|Sha384|QBFTVerifier)" \
  --no-match-test "test_report_blsBreakdown|test_report_mptDepthSensitivity|test_report_contractMode_|test_report_headerMode_" \
  --report summary --report lcov
```

`Sha384` is excluded because `forge coverage` cannot instrument its inline Yul;
the legacy `QBFTVerifier` is excluded per the workflow's TODO #443. The
`--no-match-test` cases are gas-report tests (`EthGasReport.t.sol`,
`QbftGasReport.t.sol`); per the workflow comment, `--ir-minimum` pushes the
Ethereum report's MPT-building loops past Foundry's per-call gas ceiling.

CI enforces per-metric floors (lines ≥ 92, statements ≥ 91, branches ≥ 83,
functions ≥ 100) set as workflow env (`MIN_LINES`, `MIN_STATEMENTS`,
`MIN_BRANCHES`, `MIN_FUNCS`).
Intentionally-unreachable defensive reverts belong in `coverage.excludes.md`
with a rationale, not white-boxed into coverage.

Gas: `npm run gas:check` runs the suites listed in `script/gas/baselines.yml`
and fails on any increase; `npm run gas:check:update` re-baselines (only for an
intended change, called out in the PR).

## Test file map

The tree mirrors `src/`. Key entry points:

| Path | Covers |
|---|---|
| `integration/IntegrationMock.t.sol`, `integration/IntegrationQBFT.t.sol` | Full lifecycle over `IntegrationTestBase`: register-connector → sendMessage → submitBundle → closeChannel, against `MockClprVerifier` and against `QbftHeaderModeVerifier` with the committed Besu QBFT fixtures |
| `logic/ChannelLogic.t.sol` | Channel commit/reveal (incl. pubkey-length and signature reverts); close/closing lifecycle; peer throttles and peer endpoint roster at `completeChannel`; `deriveChannelId` chain sorting |
| `logic/MessagingLogic.t.sol` | `sendMessage` gating (queue, quota, peer payload limit, `maxSyncBytes` wedge guard, reentrancy, sender stamping); `redactMessage` |
| `logic/ConnectorLogic.t.sol` | Self-authenticating commit/reveal happy/sad paths; replay protection; in-flight removal guard; stake top-up |
| `logic/AdminLogic.t.sol` | Endpoint registration and two-step admission, bonds, removal (`EndpointManagerTest`); ledger/economic config validation (`ClprService_Configuration`); kill switch; `collectPending` pull-payment |
| `logic/ManifestLib.t.sol`, `logic/PeerEndpointManifest.t.sol` | `ManifestLib` branch coverage (batch removal, full manifest); peer-manifest caching at `completeChannel`, Step 1b manifest updates, truncation to `maxPeerEndpoints`, manifest commitment coherence |
| `logic/base/LogicModuleBase.t.sol` | `onlyService` authorization |
| `logic/bundle-logic/*.t.sol` | `submitBundle` through the router, split by concern: HappyPath, Ordering (incl. source-side slashing), ClosingLogic, ErrorHandling, Configuration, PaymentPolicy, RateLimiting, TrustAnchor, PartialBundle — plus `HieroSubmitBundle.t.sol` (real service + real `HieroVerifier` + the committed `stateProof.bin` fixture) |
| `libraries/service/bundle-lib/*.t.sol` | `BundleLib` behaviour through `service.submitBundle`, twelve suites: ApplicationErrors, ControlMessages, HappyPath, ParseFailure, PartialBundle, Payment, Progress, Replay, ReplyDelivery, ResponseOrdering, StateMachine, Validation. `BundleLib_StateMachine.t.sol` also drives the state machine directly via `BundleLibHarness`; `BundleLib_ParseFailure.t.sol` swaps in `MockBundleDecodeHelper` |
| `libraries/service/ConnectorLib_*.t.sol` | Slashing and charging (incl. the B8/B9 regressions) and geometric-penalty arithmetic, via `ConnectorLibHarness` |
| `libraries/service/EndpointValidation*.t.sol` | IP-literal and DER TLS certificate validation, incl. branch coverage |
| `libraries/codec/*.t.sol` | Protobuf round-trip + fuzz for DATA / REPLY / CONTROL; varint / field-key / length-delimited primitives; config hashing |
| `libraries/crypto/*.t.sol` | `ECDSA` pubkey-length guard; `Sha384` |
| `libraries/proof/{evm,hiero,qbft,beacon}/*.t.sol` | Proof primitives per family: MPT, `RlpCursor` and EVM state proof; Hiero Merkle/state proof; QBFT seals, quorum and validator sets; BLS12-381 and beacon BLS |
| `libraries/EvmMptBuilder.t.sol` | The test-side MPT builder (`test/helpers/EvmMptBuilder.sol`), checked against the production walker |
| `verifiers/evm/qbft/*.t.sol` | `QbftHeaderModeVerifier.t.sol` and `QbftContractModeVerifier.t.sol` (proof builders in `QbftHeaderModeProofBuilders.sol` / `QbftContractModeProofBuilders.sol`); regression-gated gas baselines in `GasUsage.t.sol` (header mode) and `ContractModeGasUsage.t.sol` (contract mode); `QbftGasReport.t.sol`, the measurement suite behind `src/verifiers/evm/qbft/GAS_REPORT.md` |
| `verifiers/evm/ethereum/*.t.sol` | `EthMainnetVerifier.t.sol`; `EthMainnetWindow.t.sol` (window-encoded anchor: which window member verifies, shifts); `GasUsage.t.sol` (regression-gated BLS / SSZ hot paths); `RotationGas.t.sol`; `EthGasReport.t.sol`, the measurement suite behind `src/verifiers/evm/GAS_REPORT.md` |
| `verifiers/evm/sei/*.t.sol` | `SeiCometBftVerifier` success and error paths, real captured bundle (`SeiRealBundle.t.sol`), proto decoder, Ed25519 port, SHA-512, the verifyConfig self-certification exploit regression, `GasUsage.t.sol` |
| `verifiers/evm/avalanche/MockAvalancheVerifier.t.sol` | The mock Avalanche verifier |
| `verifiers/hiero/*.t.sol` | `HieroVerifier.t.sol`, `TSSVerifier.t.sol`, `HieroManifestLeaf.t.sol` (endpoint-manifest state-item leaf), `wraps/` (BN254, Poseidon, WRAPS), `GasUsage.t.sol` (regression-gated), `HintsGasProfile.t.sol`, and `HieroGasReport.t.sol`, the measurement suite behind `src/verifiers/hiero/GAS_REPORT.md` |
| `verifiers/compliance/*.t.sol` | Cross-verifier conformance: abstract `ClprVerifierComplianceTest` and `ClprEvmStorageComplianceTest`, with one adapter per EVM verifier — `QBFTComplianceTest` (`QbftHeaderModeVerifier`), `QbftContractModeComplianceTest` (`QbftContractModeVerifier`), `EthMainnetComplianceTest`, `SeiComplianceTest`. `VerifierComplianceCoverage.t.sol` fails CI when a concrete verifier under `src/verifiers/evm` has no adapter |
| `verifiers/stub/*.t.sol` | The two decoding stubs (see taxonomy below) |
| `compliance/ClprManifestServiceComplianceTest.t.sol` | Spec-compliance cases for the service's own endpoint-manifest obligations |
| `invariants/ClprInvariant.t.sol` | Protocol invariants under random call sequences, driven by `ClprHandler.sol` (see `test/invariants/README.md`) |
| `invariants/ClprStorageLayoutGuard.t.sol` | Pins top-level slots (incl. `Ownable._owner` at slot 38), `_clprEnabled`'s packed offset, the manifest-commitment slot and the verifier-proven `Channel` member slots against `storage-layout.json` |
| `ClprService_Constructor.t.sol` | Constructor guards (zero logic address, module not deployed) — behaviour owned by `ClprService.sol` directly, not delegated |
| `ClprService_ViewSmoke.t.sol` | Smoke test of every read-only getter across all modules |
| `ClprService_GasBenchmark.t.sol` | Gas benchmarks across all modules, including the low-overhead `MinimalMock*` doubles |
| `security/*Attacks.t.sol` | Attacker-framed restatements of the guards, one file per attack domain. Each test name carries its row id from `docs/security-test-matrix.md`, which is the canonical catalogue of vectors, defences, and classifications |
| `SafeSmartAccount.t.sol` | A real Safe v1.5.0 multisig as `ClprService` owner |

The `test/` root also holds the deployable doubles used by the e2e harness and
the `e2e-with-*` deploy modes: `E2EApplication.sol`, `E2EVerifier.sol`,
`BundleEncoderHelper.sol`. `HieroE2EVerifier.sol`, `QbftE2EVerifier.sol` and
`SeiE2EVerifier.sol` wrap the production verifiers for two-chain suites driven
by an external relay; nothing in this repo deploys them.

### Fixtures

- `test/verifiers/evm/qbft/fixtures/*.hex` are generated by
  `tools/qbft-proof-generator/` against a Besu QBFT node and **committed** —
  `IntegrationQBFT.t.sol` reads them in CI. Only the generator's side outputs
  (`metadata.json`, `debug-proof-data.json`) are gitignored.
- `test/verifiers/hiero/fixtures/` holds the committed `stateProof.bin`,
  `stateProof.json` and `trustAnchor.bin` used by the Hiero suites and
  `HieroSubmitBundle.t.sol`.
- The Sei fixture-driven tests in `SeiCometBftVerifier.t.sol` read
  `test/verifiers/sei/fixtures/` and `vm.skip` when the files are absent, which
  they are on a clean checkout.

## Verifier taxonomy (this trips people up)

Several contracts implement `IClprVerifier` in the test tree. Three matter for
unit tests; the naming is slightly misleading. `MinimalMockVerifier` is a
low-overhead stand-in for `ClprService_GasBenchmark.t.sol`, and the
`*E2EVerifier` contracts in the `test/` root are e2e doubles (above).

| Name | Path | Role | Use it when |
|---|---|---|---|
| `MockClprVerifier` | `test/mocks/MockClprVerifier.sol` | Pure setter-driven mock; ignores `proofBytes`, returns the canned `(QueueMetadata, payloads, newTrustAnchor, newTrustAnchorId, newEndpointManifest)` set via `setVerifyBundleResult`, `setNewTrustAnchor`, `setNewTrustAnchorId`, `setNewEndpointManifest` | Most tests. You want to control bundle metadata directly without producing protobuf bytes. |
| `StubBundleContentVerifier` | `test/verifiers/stub/StubBundleContentVerifier.sol` | Decodes `proofBytes` *as* a canonical `ClprBundleContent` protobuf via `ClprProtobuf.decodeBundleContent`. No prefix, no signature; trust anchor never advances; no manifest (version 0) | Hiero-to-Hiero "stub" bring-up scenarios where the bundle bytes are themselves the canonical proto |
| `StubClprVerifier` | `test/mocks/StubClprVerifier.sol` (test-only; not deployed) | Decodes `"CLPRSTUB" ‖ protobuf(ClprBundleContent)` (prefixed form) with its own two-pass decoder over `ClprProtobufHelpers`: accepts a field only on the expected field number and wire type, requires the metadata field and 32-byte running hashes | Integration tests that consume bundle bytes from an external `StubProofConstructor` (Java tooling) |

> **Mock vs Stub:** the *Mock* doesn't decode anything. Both *Stubs* are real
> decoders. `StubClprVerifier` exists because external tooling emits the
> prefixed form.

## Test base + helpers

- **`helpers/ClprTestBase.sol`** — abstract `Test` subclass providing the shared
  `service` / `verifier` / `connector` fixtures, the signer keypair, the default
  `Throttles` and `EconomicConfig` (`defaultThrottles`, `defaultEcon`, matching
  `script/ClprConfig.sol`), and helpers for deployment (`_deployClprService`,
  which deploys the five modules and `BundleDecodeHelper` via
  `ClprDeployHelper`), bootstrap (`_initializeAndEnable`), channel setup
  (`_createActiveChannel`, `_openExtraChannel`, `_deriveTestChannelId`) and
  connectors (`_registerTestConnector`, `_registerConnectorWithStake`).
  Hard-codes `localChain="eip155:1337"` and `peerChain="eip155:1"` (matching
  the chain id `_setUp` configures on the mock via `setVerifyConfigResult`;
  `MockClprVerifier` has no default). Inherit this for any test that
  creates channels; otherwise the derived id won't match the production
  derivation and `completeChannel` will fail.
- **`logic/bundle-logic/BundleLogicTestBase.sol`,
  `libraries/service/bundle-lib/BundleLibTestBase.sol`** — thin extensions of
  `ClprTestBase` with bundle submit helpers (`_submitSingleInboundMessage`,
  `_submitBundle`, `_makeConfig`). `helpers/ClprServiceTestBase.sol` adds
  nothing over `ClprTestBase`; `helpers/BundleProcessorTestBase.sol` has no
  subclasses.
- **`helpers/ConnectorRegistrar.sol`** — library; `register(service,
  channelId, seed, connectorContract, admin, stake)` does the entire
  commit/reveal-with-stake dance in one call. Different `seed` values give
  independent connectors.
- **`helpers/ClprServiceStorageSlots.sol`** — slot constants
  (`ClprServiceStorageSlots`) and mapping-slot derivations
  (`ClprStorageLayoutLib`) for `vm.load` / `vm.store`. The constants must match
  `storage-layout.json`; `ClprStorageLayoutGuardTest` checks them against it.
- **Proof helpers** — `EvmMptBuilder`, `MptWire`, `MptWalk` (MPT);
  `QbftSyntheticProofs`, `QbftContractProofs` (QBFT);
  `SeiSyntheticProofs`; `CalldataGas` (EIP-2028 calldata pricing for the gas
  reports).

Use `ClprTestBase`'s throttles/economics fixtures (`defaultThrottles`,
`defaultEcon`, `_setupDefaultConfig`, `_defaultThrottles`,
`_defaultEconomicConfig`) rather than re-declaring config in a new test file.

## Conventional `setUp`

`ClprTestBase.setUp()` already does the full bootstrap — deploy, mock
verifier and connector, `initialize(...)` + `setClprEnabled(true)`, and an
ACTIVE channel at `channelId`. Most suites only extend it:

```solidity
contract MyTest is ClprTestBase {
    function setUp() public override {
        super.setUp();           // _setUp() then _createActiveChannel()
        _registerTestConnector(); // optional: connector with 0.5 ether stake, funded
    }

    receive() external payable {}
}
```

What `_setUp()` / `_createActiveChannel()` do, if you need a variant:

```solidity
// Deploys the five logic modules + BundleDecodeHelper and feeds them to the
// nine-argument ClprService constructor.
service = _deployClprService(/*protocolVersion*/ 1, "eip155:1337");
verifier.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
verifier.setPeerThrottles(defaultThrottles);

// The service deploys with clprEnabled = false and every mutating op is
// whenEnabled; initialize() is the one owner call that runs before enabling.
_initializeAndEnable(); // initialize(hex"1234", defaultThrottles, "", "", defaultEcon), then setClprEnabled(true)

// Channel: commit keccak256(channelId ‖ pubKey), then reveal with an
// EIP-191-prefixed signature over keccak256(channelId ‖ address(service)).
service.registerChannel(channelId, commitment);
service.completeChannel(channelId, pubKey, sig, salt, address(verifier), hex"0001", "");
```

`submitBundle` is permissionless — you do not need to register an endpoint to
call it.

## Submitting a bundle in a test

1. Encode payloads with `ClprProtobuf.encode*`.
2. Compute the SHA-256 running hash chain: `h = sha256(prev ‖ sha256(payload))`,
   starting from `channel.receivedRunningHash` (`bytes32(0)` on a fresh channel).
3. Populate `ClprTypes.QueueMetadata { nextMessageId, sentRunningHash,
   receivedMessageId, receivedRunningHash, state, endpointManifestVersion }` —
   the peer's queue state. `nextMessageId` is one past the bundle's last
   message and `sentRunningHash` is the chain value through it.
4. `verifier.setVerifyBundleResult(meta, msgs)`; optionally
   `setNewTrustAnchor` / `setNewTrustAnchorId` / `setNewEndpointManifest`.
5. `service.submitBundle(channelId, hex"00FF")` — proof bytes are
   arbitrary because `MockClprVerifier` ignores them.

`BundleLibTestBase._submitSingleInboundMessage(payload)` and
`BundleLogicTestBase._submitSingleInboundMessage(payload)` do steps 2–5 for a
single, already-encoded message on a fresh channel.

### The no-progress gotcha

`BundleLib` reverts **`NoProgress`** when a bundle advances nothing: no new
messages, no new trust anchor, no endpoint-manifest advance, no ack movement,
and no state-machine transition. (`EmptyBundle` is declared but never thrown —
don't assert on it.) When testing pure state-machine transitions with no
messages and no ack progress, set `verifier.setNewTrustAnchor(hex"01")` so the
bundle has *some* effect. See
`test/libraries/service/bundle-lib/BundleLib_Progress.t.sol`.

## White-box state seeding

Two approaches are in use:

- **`vm.store` against `storage-layout.json` slots.** `AdminLogic.t.sol`'s
  `collectPending` tests seed `_pendingWithdrawals` (slot 11) this way;
  `BundleLib_StateMachine.t.sol` forces a channel's status;
  `PeerEndpointManifest.t.sol` and `ClprManifestServiceComplianceTest` also
  write storage directly. Take slot numbers from `ClprServiceStorageSlots`
  rather than hard-coding new ones.
- **Library harnesses** that expose `internal` functions with crafted inputs:
  `ConnectorLibHarness` (`ConnectorLib_SlashAndCharge.t.sol`,
  `ConnectorLib_GeometricPenalty.t.sol`), `EndpointValidationHarness`,
  `BundleLibHarness`, `EcdsaHarness`, `ClprProtobufHarness`, and the verifier
  harnesses in `test/helpers/` (`TSSVerifierHarness`, `WRAPSVerifierHarness`,
  `SeiCometBftVerifierHarness`, and `QbftContractHarness.sol`'s
  `ContractSourceHarness` / `OpenCommitmentHarness`).

The invariant suite seeds pull-payment balances organically instead:
`ClprHandler.submitInboundSlashPendingEthRejector` and
`submitInboundChargeFailSlashPendingEthRejector` make an `EthRejector`
(`test/mocks/EthRejector.sol`) the bundle submitter and, for the duration of
the call, the service owner, so the slash transfer and its fallback both fail
and land in `_pendingWithdrawals`.

If you need to seed something else, add a new harness alongside the test
that needs it; do not expose internals on `ClprService` itself.

## Coverage gaps to be aware of

- Alternative lifecycle paths (multi-bundle drain, peer-initiated close,
  redact-then-bundle) are tested as fragments across
  `test/logic/bundle-logic/` and `test/libraries/service/bundle-lib/` rather
  than as whole scenarios.
- Two tests are tagged `B8` and `B9`
  (`test/libraries/service/ConnectorLib_SlashAndCharge.t.sol`) — they pin the
  pull-payment fallback and the auto-ban-on-stake-zero behaviour. Don't simplify
  them away without reading them.
- There is **no Hiero adapter** in `test/verifiers/compliance/`, unlike the
  QBFT, Sei and Ethereum families. `VerifierComplianceCoverage.t.sol` scans only
  `src/verifiers/evm`, so it does not flag this.
- The legacy `QBFTVerifier` has no Forge suite and is excluded from both the
  compliance-coverage check and the coverage run (TODO #443 in
  `VerifierComplianceCoverage.t.sol` and the Coverage workflow step). It is
  exercised only through the e2e harness (e.g.
  `test/e2e/tests/verifiers/qbft-verifier.spec.ts`).
- `EthMainnetComplianceTest.test_compliance_verifyConfig_revertsOnCorruptedProof`
  is `vm.skip`ped (TODO #333 in the test).

## StubClprVerifier placement and round-trip test

`StubClprVerifier` lives at `test/mocks/StubClprVerifier.sol`. This is the
correct location — it is a test-only decoder and is not part of any
production deployment. The first-party round-trip test is in
`test/verifiers/stub/StubClprVerifier.t.sol`. It:

1. Builds a `ClprTypes.QueueMetadata` and a list of `ClprMessagePayload` byte
   arrays in Solidity using `ClprProtobuf` encoders.
2. Encodes them via `ClprProtobuf.encodeBundleContent(meta, payloads)`.
3. Prefixes the result with the 8-byte magic `"CLPRSTUB"` to form `proofBytes`.
4. Passes `proofBytes` to `StubClprVerifier.verifyBundle(proofBytes, "", "")` and
   asserts that the decoded metadata and payloads match the inputs exactly.

It also checks that bytes without the prefix revert with
`"StubVerifier: missing CLPRSTUB prefix"`.

## End-to-end suite (Vitest)

`test/e2e/` deploys `ClprService` on two local chains through the
`script/deploy/` library and ferries bundles between them; see
`test/e2e/README.md` for backends, prerequisites and state files. Run
`forge build` first — the harness consumes `out/*.json`.

```bash
npm run test:e2e                 # = test:e2e:anvil, no Docker
npm run e2e:up:besu && npm run test:e2e:besu && npm run e2e:down:besu
npm run e2e:up:solo && npm run test:e2e:solo && npm run e2e:down:solo
npm run e2e:up:besu:solo && npm run test:e2e:besu:solo && npm run e2e:down:besu:solo   # cross-verifier
npm run test:e2e:qbft-verifier   # also: test:e2e:eth-verifier, test:e2e:sei-verifier
```

Always run the matching `e2e:down*` script when finished — the compose
volumes and kind clusters persist otherwise.
