#!/usr/bin/env bash
# Opens a channel and enqueues three Data Messages on the running localnet, then sets the
# endpoint manifest. Prints the channel id. Used to record the Hiero-side fixture.
set -euo pipefail
cd "$(dirname "$0")/.."
HOME_DIR=${CLPRD_HOME:-$PWD/build/home}
F=(--home "$HOME_DIR" --keyring-backend test --node "tcp://127.0.0.1:${CLPRD_RPC_PORT:-36657}"
   --chain-id "${CLPRD_CHAIN_ID:-dydx-clpr-local-1}" -y --gas 400000 --output json)
tx() { local out; out=$(./build/clprd tx clpr "$@" --from alice "${F[@]}"); echo "$out" | jq -c '{code,txhash}' >&2
       [ "$(echo "$out" | jq .code)" = 0 ] || exit 1; sleep 3; }
CH=$(printf 'clpr-dydx-hiero-demo' | shasum -a 256 | cut -c1-64)
MOD=$(printf 'clpr' | shasum -a 256 | cut -c1-40)          # module account = sha256("clpr")[:20]
CONN=$(printf 'connector' | shasum -a 256 | cut -c1-64)
tx open-channel "$CH"
for d in 68656c6c6f20686965726f 6d7367 32; do
  tx send-message "$CH" "$CONN" 000000000000000000000000000000000000abcd "$d"
done
tx update-manifest "08011214$MOD"   # ClprEndpointManifest{version: 1, service_address: module}
echo "$CH"
