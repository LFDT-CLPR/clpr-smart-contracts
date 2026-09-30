# Release Process

Releases of `clpr-smart-contracts` follow the same process as the sibling contract repositories: 
a manually dispatched workflow computes the next version from Conventional Commits, builds
the contracts deterministically, packages a reproducible artifact bundle, generates release
notes, and publishes a signed tag plus a GitHub Release.

Everything is driven by
[`.github/workflows/100-user-publish-contracts.yaml`](../.github/workflows/100-user-publish-contracts.yaml)
(`100: [USER] Publish Contracts`). There is no automatic release on merge — cutting a
release is always a deliberate act.

## What a release contains

The deliverable of this repository is EVM bytecode, so the release artifact is a
reproducible archive of the compiled contract surface an integrator needs:

```
clpr-smart-contracts-<version>/
  abi/                 <Contract>.abi.json          (jq -S canonicalised)
  bytecode/            <Contract>.bytecode.hex      (creation bytecode)
                       <Contract>.deployed-bytecode.hex
  storage-layout/      ClprService.storage-layout.json
  manifest.json        name, version, commit, forge + solc settings, contract list
  LICENSE
```

Packaged contracts: `ClprService`, the five logic modules (`ChannelLogic`,
`MessagingLogic`, `BundleLogic`, `ConnectorLogic`, `AdminLogic`), `BundleDecodeHelper`,
and the production verifiers (the legacy `QBFTVerifier` and the two QBFT mode verifiers,
`QbftHeaderModeVerifier` and `QbftContractModeVerifier`; `HieroVerifier`, `TSSVerifier`,
`EthMainnetVerifier`, `SeiCometBftVerifier`, `Ed25519Verifier`).

The Hiero verifier's on-chain dependencies ship alongside it — `PoseidonPermuteA`,
`PoseidonPermuteB`, `PoseidonBN254Contract`, and `WRAPSVerifierContract`. A
`HieroVerifier` cannot be stood up without them: `deployHieroVerifierStack` in
`script/deploy/deployCore.ts` deploys the stack bottom-up (Poseidon primitives →
`PoseidonBN254Contract` → `WRAPSVerifierContract` → `TSSVerifier` → `HieroVerifier`),
each taking the previous addresses as constructor arguments.

Interfaces (`IClprService`, `IClprApplication`, `IClprConnector`, `IClprVerifier`,
`ILogicModule`) ship ABI only. Test doubles and test-only helpers are deliberately
excluded: `MockAvalancheVerifier`, `E2EApplication`, `E2EVerifier`, `MockClprConnector`,
and `BundleEncoderHelper` (a `test/` helper that exposes the protobuf encoder to the
E2E relay over `eth_call` — despite the name, unrelated to the published
`BundleDecodeHelper`, which is production code whose address `ClprService` holds as an
immutable).

Two assets are attached to the GitHub Release: `clpr-smart-contracts-v<X.Y.Z>.tar.gz`
and its `.sha256` sidecar.

## Reproducibility

The bundle is byte-for-byte reproducible from a given commit:

- Bytecode is deterministic given the pinned `solc 0.8.30` + `via_ir` + `optimizer_runs`
  settings in `foundry.toml`. `bytecode_hash = "none"` and `cbor_metadata = false` strip
  the trailing CBOR metadata, so the bytes don't vary with source paths.
- ABIs are canonicalised with `jq -S` (sorted keys).
- The tarball is normalised: sorted entries, fixed mtime (`SOURCE_DATE_EPOCH`, taken from
  the commit date), `uid`/`gid` zeroed, and `gzip -n` so no timestamp is embedded.

The workflow **packs the bundle twice into different paths and fails the release if the
checksums differ** — a non-deterministic build stops the release rather than shipping
silently.

You can reproduce a published bundle locally:

```shell
git checkout v<X.Y.Z>
forge build src --deny warnings
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)" \
  .github/workflows/support/scripts/pack_release_artifact.sh <X.Y.Z> dist/clpr-smart-contracts-v<X.Y.Z>.tar.gz
sha256sum -c dist/clpr-smart-contracts-v<X.Y.Z>.tar.gz.sha256
```

The script needs GNU `tar` and `jq`. On macOS install GNU tar (`brew install gnu-tar`) —
the script picks up `gtar` automatically and falls back to `shasum -a 256`.

## Versioning

Versions come from [`git-semver`](https://github.com/mdomke/git-semver) reading the
Conventional Commit history since the previous tag — the same tool `hiero-consensus-node`
uses. This is why PR titles matter: squash-merge makes the PR title the commit subject,
and `feat:` / `fix:` / `feat!:` are what drive the next version.

The project is pre-1.0, so the workflow passes `--stable=false`: a breaking change bumps
the **minor**, not the major. When the project moves to a stable 1.x line, remove that flag.

Tags are `v<semver>` per [`docs/branch-naming-conventions.md`](branch-naming-conventions.md),
annotated and **GPG-signed** (the `[Tag] Layer 1` ruleset requires signed tags and blocks
unsigned or force-updated ones).

## Cutting a release

1. **Dry run first.** Actions → `100: [USER] Publish Contracts` → *Run workflow*. Leave
   `dry-run-enabled` checked (the default). The run computes the version, builds, packs,
   verifies reproducibility, and renders the notes — but creates no tag and no release.
   The bundle and `RELEASE_NOTES.md` are attached as workflow artifacts, and the notes are
   printed to the job summary.
2. **Review** the computed version and the rendered notes in the job summary.
3. **Re-run with `dry-run-enabled` unchecked** to publish. This additionally imports the
   signing key, creates and pushes the signed `v<X.Y.Z>` tag, and creates the GitHub
   Release with the notes as the body and both assets attached.

### Inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `ref` | *(empty)* | Commit, branch, or tag to release from. Empty releases the dispatched ref's HEAD. Passing an **existing tag** reuses that version verbatim and skips tagging — use it to re-run a failed publish. |
| `alpha-release` | `false` | Cut a pre-release (`vX.Y.Z-alpha.N`). Marks the GitHub Release as a pre-release and does not move `latest`. |
| `dry-run-enabled` | `true` | Compute and build only. Uncheck to actually tag and publish. |

Every run prints a ready-to-paste `gh workflow run …` command in its summary
(the `Re-run command` job) replaying the same inputs.

### Idempotency

Re-running a publish is safe. If the tag already exists it is not recreated, and
`skipIfReleaseExists` means an existing Release is left alone. That makes the common
failure mode — tag pushed but Release creation failed — recoverable by simply re-running
with `ref` set to the tag.

## Point-in-time releases

The release *tooling* is checked out separately from the release *source*, via a sparse
checkout of `.github/workflows/support` at the workflow's own ref. Cutting a release of an
older commit therefore uses today's packaging and release-note scripts, not whatever
existed at that commit (which may predate the tooling entirely).

## Required configuration

The workflow depends on repository-level secrets and variables:

| Name | Kind | Used for |
|------|------|----------|
| `GH_ACCESS_TOKEN` | secret | Checkout, pushing the tag, and creating the Release. A PAT rather than `GITHUB_TOKEN` so the tag push can trigger downstream tag-driven workflows. |
| `GPG_KEY_CONTENTS` | secret | Private key used to sign the tag. |
| `GPG_KEY_PASSPHRASE` | secret | Passphrase for that key. |
| `GIT_USER_NAME` | variable | Committer/tagger name. |
| `GIT_USER_EMAIL` | variable | Committer/tagger email. |

The identity behind `GH_ACCESS_TOKEN` must be in one of the `[Tag] Layer 1` ruleset's
bypass teams (`automation`, `automation-admin`, or the CLPR maintainers team), since
that ruleset otherwise blocks tag creation outright.

## Consuming a release

Downstream consumers obtain published contract bundles by downloading the release
tarball, verifying its `.sha256`, and rehydrating `abi/` + `bytecode/` into the Foundry
`out/` layout so released bytecode is broadcast verbatim rather than recompiled. The
bundle layout here matches what that rehydration step expects from the sibling contract
repositories.
