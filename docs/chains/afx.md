# AFX L1 → Hiero

Status: blocked. AFX publishes no node source, no consensus specification, no public node RPC
and no signed artefact that commits to its state. Nothing exists for a verifier to check.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | none published (DefiLlama "AFX L1", `chainId` null). Order signing uses EIP-712 with chain id 42161 (mainnet) / 421614 (testnet), i.e. Arbitrum's ids |
| Chain type | Perpetuals app-chain ("Anti-Fragile Exchange", afx.xyz, GitHub org `afx-dex`). Press describes "Mysticeti-based DAG BFT" with an "ABCI/Cosmos SDK modular structure"; not confirmed by any source or doc |
| Finality source | Unknown. No block, checkpoint or certificate format is documented or served |
| Signature scheme | Unknown for consensus. The Arbitrum bridge uses secp256k1 EIP-712 signatures of 7 validators, but only over withdrawals and validator-set updates |
| State commitment | None published |
| Verifier | none |
| Trust tier | — |
| Typical bundle / rotation | — |

## Classification

**(c) Blocked.** Every input a CLPR verifier needs is missing:

1. A finality artefact (block or checkpoint certificate, signature scheme, committee definition).
2. A state or app-hash commitment inside that artefact.
3. An inclusion-proof API for state or events.
4. A contract or VM layer where a CLPR queue could live.
5. Node source to check any of the above against.

Even the attestor ("signer") family does not apply without AFX: its only known signers are the 7
bridge validators, and they would have to agree to sign CLPR tuples.

## Evidence (2026-10-01)

| Check | Result |
|---|---|
| Public code | `afx-dex` has 7 repositories: docs, JS and Python trading SDKs, agent kits, DefiLlama adapter forks. No node, consensus or execution code |
| Docs | docs.afx.xyz (incl. `llms-full.txt`) describe trading APIs only; nothing on validators, nodes, blocks or proofs |
| Node RPC | none found; guessed `rpc`/`lcd`/explorer hostnames under afx.xyz do not resolve |
| Info API | `/info/explore/block/detail` returns error 40003 at every height tried; mainnet `product-meta` returns an empty `perpProducts` list; the websocket `block` channel accepts a subscription and sends nothing in 40 s |
| DefiLlama | TVL flat at exactly $12,225,918 from 2026-09-27 to 2026-10-01; the adapter's source `api.afx.xyz/.../lp/summary` returns 40003 (the figure is likely stale) |
| Bridge | Arbitrum `0xCb3B9A3E5668AFE84DC7A864B36b845dCE062e67` (Sourcify-verified): a near copy of Hyperliquid's Bridge2 (hot/cold sets, > 2/3 power, 200 s dispute). Epoch 0 (never rotated), 7 validators, power 10,000. Holds 0 USDC; 24.15M USDC left through `batchedFinalizeWithdrawals` on 2026-07-22; last outflow seen 2026-08-17 |

## What would unblock it

- AFX publishes a node (or at least a consensus and state specification) and a public RPC that
  serves signed commits/checkpoints and state or event inclusion proofs.
- If the chain is Mysticeti/Sui-style, a committee-signed checkpoint (BLS12-381 aggregate) over a
  state or effects digest would fit the BLS-committee family (in progress) with EIP-2537.
- If it is CometBFT/ABCI-based, an `app_hash` with ICS-23 proofs would fit the CometBFT family.
- Before spending effort: confirm the chain still operates (empty product list, drained bridge,
  stale TVL).

## Deployment profile

Not defined.

## Relayer requirements

Not defined; no data source exists.

## Chain-specific trust and caveats

The only verifiable on-chain fact is the Arbitrum bridge: 7 validators, > 2/3 of power, epoch 0.
They sign bridge actions, not chain state.

## Live verification

None possible. Probes listed above (afx.xyz, docs.afx.xyz, `afx-dex` repositories, Arbitrum
`eth_call`/`eth_getLogs` on the bridge and USDC, DefiLlama `api.llama.fi` chain and protocol data).

## Hiero → AFX

Not possible without a programmable layer on AFX.
