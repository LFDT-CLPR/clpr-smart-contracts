# CLPR Smart Contracts

Solidity contracts for the CLPR protocol, built with [Foundry](https://book.getfoundry.sh/).

## Quick Start

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Clone and install

```shell
git clone --recurse-submodules https://github.com/hiero-hackers/clpr-smart-contracts.git
cd clpr-smart-contracts
```

Dependencies are pinned as git submodules:

| Package | Version | Pinned commit |
|---------|---------|--------------|
| [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) | v1.15.0 | `0844d7e1fc5e60d77b68e469bff60265f236c398` |
| [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | v5.7.0 | `cab19933c33c2ad1d4c7a84864a3601dddfd16f3` |

If you cloned without `--recurse-submodules`, run `forge install` to populate `lib/`.

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Fuzz testing

```shell
forge test --fuzz-runs 10000
```

Fuzz runs default to 256. Increase via `--fuzz-runs` or in `foundry.toml`:

```toml
[fuzz]
runs = 10000
```

### Coverage

```shell
forge coverage --report lcov
```

### Format

```shell
forge fmt
```

### Storage layout snapshot

The file `storage-layout.json` is the committed output of:

```shell
forge inspect ClprService storage-layout --json > storage-layout.json
```

It captures the linearized storage layout of `ClprService` (including `ClprServiceStorage` and inherited OpenZeppelin state). Logic contracts delegate into that layout, so shifting slots breaks assumptions and any future proxy-style upgrade path. See [`docs/lifecycle.md`](docs/lifecycle.md) for protocol-specific encoding and state discipline.

CI regenerates this JSON after `forge build` and fails if it differs from the committed file. If your PR changes storage on purpose, run `forge build` then the `forge inspect` command above, review the resulting diff to `storage-layout.json`, and commit the update with a clear message. CI uses the Foundry version pinned in `.github/workflows/600-flow-pull-request-checks.yaml`; if your local `forge` differs, refresh the snapshot using that version or rely on CI to show the expected JSON before you commit.

## Deployment

All deploys go through **viem** in `script/deploy/` (`npm run deploy` or `bin/deploy.sh`). The CLI deploys logic modules (`ChannelLogic`, `MessagingLogic`, `BundleLogic`, `ConnectorLogic`, `AdminLogic`), `BundleDecodeHelper`, and `ClprService`. When the deployer key also owns the contract, it calls `initialize()` to apply the initial `LedgerConfiguration` and `EconomicConfig` atomically. When the owner is a multisig, deploy stops after construction and logs the admin calls the multisig must submit.

`clprEnabled` defaults to `false` on deploy — the service is inert until explicitly enabled, even after config is applied. Pass `--auto-enable` to have the script call `setClprEnabled(true)` as the last step (useful for e2e/local-dev runs that need an immediately-usable service). Omit it for production/testnet deploys, where enabling should be a deliberate, separate step after reviewing the applied config — see [Post-deploy multisig checklist](#post-deploy-multisig-checklist).

### Output

Deployed addresses are **always printed to stdout as a JSON object**. All human-readable progress logs go to stderr, so stdout is safe to `JSON.parse` (or pipe through `jq`) directly.

> **Capturing output:** `npm run` prints its own banner (`> deploy` / `> tsx …`) to stdout *before* the CLI runs, which corrupts captured JSON. When redirecting or capturing stdout, either add `--silent` to npm (`npm run --silent deploy -- …`) or call the CLI directly with `npx tsx script/deploy/cli.ts …`, which has no banner.

| Flag | Effect |
|------|--------|
| `--output <fmt>` | Output format. Only `json` is supported today; the flag exists so other formats can be added later. Default: `json`. |
| `--output-to-file [path]` | Also write the output to a file. With a path, that path is used; without one, it defaults to `clpr-deployed-addresses.json` in the current directory. When omitted, no file is written — stdout output is always printed regardless. |
| `--auto-enable` | Call `setClprEnabled(true)` as the last step of config application (only takes effect when this run applies config, i.e. deployer == owner). Default: off — `clprEnabled` stays `false` until a separate, explicit `setClprEnabled(true)` call. |

For the e2e modes, the output includes the helper contracts (`E2E_APPLICATION`, `MOCK_CLPR_CONNECTOR`, `BUNDLE_ENCODER_HELPER`) alongside the core addresses, so consumers get the complete set from stdout without reading stderr.

```shell

# print deployed addresses as JSON to stdout
npm run deploy -- all --rpc-url anvil

# also write the JSON to a file (defaults to clpr-deployed-addresses.json)
npm run deploy -- all --rpc-url anvil --output-to-file

# write to a specific path
npm run deploy -- all --rpc-url anvil --output-to-file deployments/anvil.json

# redirect stdout to a file — use --silent so npm's banner doesn't corrupt the JSON
npm run --silent deploy -- all --rpc-url anvil 2>/dev/null > deployments/anvil.json

# capture the JSON in a shell variable (call tsx directly to avoid npm's banner)
ADDRS=$(npx tsx script/deploy/cli.ts all --rpc-url anvil 2>/dev/null)
echo "$ADDRS" | jq -r '.CLPR_SERVICE'
```

Example JSON shape (keys mirror the env var names):

```json
{
  "CLPR_SERVICE": "0x…",
  "CHANNEL_LOGIC": "0x…",
  "MESSAGING_LOGIC": "0x…",
  "BUNDLE_LOGIC": "0x…",
  "CONNECTOR_LOGIC": "0x…",
  "ADMIN_LOGIC": "0x…",
  "BUNDLE_DECODE_HELPER": "0x…"
}
```

### Environment variables

Copy `.env.example` to `.env` and fill in the values. The script reads:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PRIVATE_KEY` | yes | — | Deployer key. Signs the deploy tx. |
| `INITIAL_OWNER` | no | `vm.addr(PRIVATE_KEY)` | Address that owns `ClprService` after construction. For prod, the multisig. Defaults to the deployer (so local anvil runs also apply initial config in one broadcast). |
| `OWNER_ACCOUNT` | no (required with `--transfer-ownership-to-account`) | — | Address ownership of `ClprService` is transferred to when `--transfer-ownership-to-account` is passed. Typically a Safe multisig. |
| `PROTOCOL_VERSION` | no | `1` | Baked into `LedgerConfiguration` at construction. |
| `CHAIN_ID` | no | `eip155:1` | String chain id baked into `LedgerConfiguration`. |
| `SERVICE_ADDRESS` | no | empty | Service address applied via `updateLedgerConfiguration` when deployer == owner. |
| `ECON_*` | no | see `script/ClprConfig.sol` | Per-field overrides for `EconomicConfig`. |
| `DEPLOY_GAS` | no | RPC auto-estimation | Manual gas-limit override for deployment transactions, bypassing RPC auto-estimation. Set this if your target RPC's `eth_estimateGas` misbehaves for contract-creation txs (e.g. pre-v0.159.0 Hiero Mirror Node — see the `HIERO_RPC` row below). |
| `BESU_RPC` | no (`--rpc besu` with full URL) | — | RPC URL for the `besu` alias in `foundry.toml`. Not needed when running `bin/deploy.sh --rpc besu`, which manages the local compose stack and rewrites `$RPC` to the resolved host URL. |
| `HIERO_RPC` | no (hiero only) | — | RPC URL referenced by the `hiero` alias in `foundry.toml`. Requires **Mirror Node v0.159.0 or later** (the default in Solo v0.83.0+) — earlier versions return `INSUFFICIENT_TX_FEE` from `eth_estimateGas` for contract-creation txs from ECDSA senders (hiero-ledger/hiero-mirror-node#13820), which breaks deployment unless `DEPLOY_GAS` is set manually. |
| `BESU_NODE` | no (`bin/deploy.sh --rpc besu`) | `a` | Selects which compose node to target: `a` (chainId 1337) or `b` (chainId 1338). |
| `BESU_RPC_A`, `BESU_RPC_B` | written by wrapper | — | Resolved compose host URLs (random port per `e2e:up`). The wrapper writes them to `.env` after starting the stack so subsequent runs / external tools can reuse them. |

### Ownership transfer

Pass `--transfer-ownership-to-account` to transfer ownership of the freshly-deployed `ClprService` to the address in `OWNER_ACCOUNT` (typically a Safe multisig) as the final step of the run. The transfer targets the ClprService deployed in the current run; for `config`-only mode (no deploy this run) it falls back to `CLPR_SERVICE` from the env.

```shell
export OWNER_ACCOUNT=0x…            # the Safe (or other) address to own ClprService
npm run deploy -- all --rpc-url besu --transfer-ownership-to-account
```

See [`docs/safe-runbook.md`](docs/safe-runbook.md) for operating the Safe multisig once it owns `ClprService` (signer rotation, threshold changes, emergency procedures).

### Local (anvil)

```shell
anvil &
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export INITIAL_OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266   # = deployer
npm run deploy -- all --rpc-url anvil
# or: bin/deploy.sh all --rpc anvil
```

For the full e2e stack with production `HieroVerifier`:

```shell
# ledger id: LEDGER_ID / TRUST_ANCHOR in .env, or test/verifiers/hiero/fixtures/trustAnchor.bin
npm run deploy:e2e-with-hiero-verifier -- --rpc-url anvil
# or: npm run deploy -- e2e-with-hiero-verifier --rpc-url besu
```

Deployed addresses are printed to stdout as JSON. To also write them to a file, add `--output-to-file [path]` (defaults to `clpr-deployed-addresses.json`). The `e2e-with-hiero-verifier` mode includes `HIERO_VERIFIER` and the Poseidon / WRAPS / TSS helper contracts in its output.

### Besu

For deploying to a remote Besu node you already manage, the `besu` aliases in `foundry.toml` resolve to the `BESU_RPC` env vars:

```shell
export BESU_RPC=http://your-besu-node:8545        # or HIERO_RPC for Hiero
export PRIVATE_KEY=<deployer key>
export INITIAL_OWNER=<multisig address>
npm run deploy -- all --rpc-url besu   # add --output-to-file to also write a JSON file
```

For the **local two-node compose stack** (the same one `npm run test:e2e:besu` uses), use the wrapper script with `--rpc besu` — see below.

### Wrapper script (interactive + scoped deploys)

`bin/deploy.sh` is a bash wrapper around `script/deploy/cli.ts` that:

- Presents two interactive menus in TTY mode: first **backend** (anvil / besu / custom alias or URL), then **mode**. Refuses to auto-deploy silently from a pipe or CI without an explicit mode.
- Validates required env vars per mode before invoking the viem CLI; missing values produce a clean error with the list of what's needed.
- Auto-starts anvil in the background when `--rpc anvil` and nothing is listening on `http://127.0.0.1:8545`; prints the PID for manual cleanup.
- Auto-manages the local two-node Besu compose stack when `--rpc besu`: invokes `npm run e2e:up` if either container is missing, resolves the dynamic host ports via `docker compose ps`, polls `eth_chainId` until both nodes answer (asserting the expected 1337 / 1338), rewrites the RPC to the chosen node's URL, and persists `BESU_RPC_A` / `BESU_RPC_B` to `.env`. Select the target node with `BESU_NODE=a` (default) or `BESU_NODE=b`.
- Passes the deployed-address JSON from the CLI through to the terminal. The CLI prints addresses as JSON on stdout; the wrapper's own status/progress messages go to stderr.
- Logs each deployed contract individually after parsing the receipt (`ContractName → 0x…`), filtering out the per-call admin txs so only `CREATE` transactions surface as deployments.

```shell
# Interactive (TTY): pick backend, then mode
bin/deploy.sh

# Non-interactive against anvil (auto-started if not running)
bin/deploy.sh all      --rpc anvil    # modules + service + config
bin/deploy.sh modules  --rpc anvil    # only the 6 logic modules + BundleDecodeHelper
bin/deploy.sh service  --rpc anvil    # only ClprService, reusing module addrs
bin/deploy.sh config   --rpc anvil    # sends updateLedgerConfiguration + updateEconomicConfiguration transactions

# Non-interactive against the local Besu compose stack (auto-ups if needed)
BESU_NODE=a bin/deploy.sh all     --rpc besu   # deploy onto chainId 1337
BESU_NODE=b bin/deploy.sh modules --rpc besu   # only modules onto chainId 1338

# Non-interactive against an arbitrary RPC (your own alias from foundry.toml or a URL)
bin/deploy.sh all --rpc https://my-node.example:8545
bin/deploy.sh all --rpc my-alias                 # alias must exist in foundry.toml
```

Tear down the Besu stack when done: `npm run e2e:down` (the wrapper does not stop it on exit; the docker volumes are removed by `e2e:down`).

Each mode declares its required env vars; the wrapper refuses to run if any are missing:

| Mode | Required env vars |
|------|-------------------|
| `all` | `PRIVATE_KEY` (`INITIAL_OWNER` optional; defaults to deployer) |
| `modules` | `PRIVATE_KEY` |
| `service` | `PRIVATE_KEY`, `CHANNEL_LOGIC`, `MESSAGING_LOGIC`, `BUNDLE_LOGIC`, `CONNECTOR_LOGIC`, `ADMIN_LOGIC`, `BUNDLE_DECODE_HELPER` |
| `config` | `PRIVATE_KEY`, `CLPR_SERVICE` |

The `service` and `config` modes read module/service addresses from your environment — the wrapper sources `.env` at startup. Deploys print addresses as JSON; they are **not** written back to `.env` automatically. To run the scoped modes in sequence, capture the addresses from one step's JSON output and set them in your environment (or `.env`) before the next:

```shell
bin/deploy.sh modules    # prints module addresses as JSON
# set CHANNEL_LOGIC / MESSAGING_LOGIC / … in your env or .env from that output
bin/deploy.sh service    # reads those, prints CLPR_SERVICE as JSON
# set CLPR_SERVICE in your env or .env from that output
bin/deploy.sh config     # applies initial ledger + economic config
```

> **Note:** neither the CLI nor the wrapper writes deployed addresses back to `.env` — addresses are emitted as JSON on stdout only. If you rely on later scoped modes reading earlier addresses, populate them into your environment (or `.env`) yourself between steps, e.g. with `--output-to-file` and a small script, or by running `all` in a single pass. The one-shot `all` mode avoids the hand-off entirely.

#### Deployment ordering

`service` mode requires all five module contracts (`ChannelLogic`, `MessagingLogic`, `ConnectorLogic`, `AdminLogic`, `BundleDecodeHelper`) to already be deployed on the target RPC. The wrapper enforces this in two layers:

1. The five module env vars must be set (env validation, exit code `3`).
2. Each module address must have non-empty bytecode at the target RPC — verified via `cast code` before the forge call (exit code `6`). This prevents constructing a `ClprService` that would `delegatecall` into the void.

If you see `error: the following module addresses have no deployed bytecode`, run `./bin/deploy.sh modules --rpc <alias>` first, then re-run `service`.

> **Follow-up (out of scope for this PR):** the current design ties module-deploy order to address-fixing-time. A future change could compute module addresses via CREATE2 (or the foundry deterministic-deployment proxy at `0x4e59b441…`) so `service` could be deployed first and modules later in any order. That would also enable cross-network address parity, at the cost of bytecode-versioning discipline.

Exit codes: `0` success, `2` usage error, `3` missing env or zero-balance deployer, `4` missing `npx` / `anvil` / `docker` / `npm` / `cast` (the besu path also fails here if the compose stack can't be brought up or `eth_chainId` doesn't respond within 60s), `6` `service` mode invoked with un-deployed module addresses. `docker` and `npm` are only required for the `--rpc besu` path.

### Post-deploy multisig checklist

When `INITIAL_OWNER` differs from the deployer (the production case), the script does **not** apply initial config — the multisig must submit two transactions from the owner account after the deploy, **in this order**:

1. `initialize(serviceAddress, throttles, trustAnchor, trustAnchorId, econConfig)` — applies both the ledger and economic configuration atomically, in a single transaction, **while the service is still disabled**. Default throttles and economics are in `script/ClprConfig.sol::defaultThrottles()` and `defaultEconomicConfig()`; the deploy CLI takes the service address and trust anchor from `SERVICE_ADDRESS`, `TRUST_ANCHOR` and `TRUST_ANCHOR_ID` (`script/deploy/config.ts`). Reverts if called more than once (`ClprAlreadyInitialized`).
2. `setClprEnabled(true)` — `clprEnabled` defaults to `false` on deploy; the service is inert until this call, and this call itself reverts (`ClprNotInitialized`) unless step 1 has already landed. Submit it once you've confirmed the config applied in step 1 is correct.

Because step 1 is a single atomic transaction that sets both configs before anything is enabled, there's no intermediate window where the service is live with default (zero-value) config — unlike `updateLedgerConfiguration`/`updateEconomicConfiguration` (which remain available, individually, for *later* reconfiguration once the service is already running), `initialize()` exists specifically to close that gap for the bootstrap case.

The script's console output summarizes this checklist along with all deployed addresses.

## Operations

Runbooks for operating a live deployment:

- [`docs/runbooks/kill-switch.md`](docs/runbooks/kill-switch.md) — when and how to flip the `setClprEnabled(false)` kill switch during an incident (triggers, Safe invocation via `cast`, verification, re-enabling, paging tree, post-mortem template).
- [`docs/safe-runbook.md`](docs/safe-runbook.md) — operating the Safe multisig that owns `ClprService`: signer rotation, threshold changes, transaction signing, emergency procedures.

## Project structure

```
src/       Solidity contracts
test/      Forge tests
script/    Deployment scripts
lib/       Dependencies
```