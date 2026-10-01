#!/usr/bin/env bash
# One-validator local chain running x/clpr on dYdX's SDK/CometBFT forks.
#   scripts/localnet.sh init   # fresh home in $CLPRD_HOME (default ./build/home)
#   scripts/localnet.sh start  # runs the node in the foreground
# RPC on 127.0.0.1:${CLPRD_RPC_PORT:-36657}. Test keyring only; keys are throwaway.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=./build/clprd
HOME_DIR=${CLPRD_HOME:-$PWD/build/home}
CHAIN_ID=${CLPRD_CHAIN_ID:-dydx-clpr-local-1}
RPC_PORT=${CLPRD_RPC_PORT:-36657}
P2P_PORT=${CLPRD_P2P_PORT:-36656}
GRPC_PORT=${CLPRD_GRPC_PORT:-39390}
K="--keyring-backend test --home $HOME_DIR"

case "${1:-}" in
init)
  rm -rf "$HOME_DIR"
  $BIN init validator --chain-id "$CHAIN_ID" --default-denom adydx --home "$HOME_DIR" >/dev/null 2>&1
  $BIN keys add validator $K >/dev/null 2>&1
  $BIN keys add alice $K >/dev/null 2>&1
  $BIN genesis add-genesis-account "$($BIN keys show validator -a $K)" 1000000000000000000000adydx --home "$HOME_DIR"
  $BIN genesis add-genesis-account "$($BIN keys show alice -a $K)" 1000000000000000000000adydx --home "$HOME_DIR"
  $BIN genesis gentx validator 100000000000000000000adydx --chain-id "$CHAIN_ID" $K >/dev/null 2>&1
  $BIN genesis collect-gentxs --home "$HOME_DIR" >/dev/null 2>&1
  # x/clpr admin = alice (may update the manifest; gov is the keeper authority).
  ALICE=$($BIN keys show alice -a $K)
  G="$HOME_DIR/config/genesis.json"
  jq --arg a "$ALICE" '.app_state.clpr.params.admin=$a' "$G" > "$G.tmp" && mv "$G.tmp" "$G"
  C="$HOME_DIR/config/config.toml"
  sed -i.bak -e "s#^laddr = \"tcp://127.0.0.1:26657\"#laddr = \"tcp://127.0.0.1:$RPC_PORT\"#" \
             -e "s#^laddr = \"tcp://0.0.0.0:26656\"#laddr = \"tcp://127.0.0.1:$P2P_PORT\"#" \
             -e 's#^timeout_commit = .*#timeout_commit = "1s"#' \
             -e 's#^pprof_laddr = .*#pprof_laddr = ""#' "$C"
  A="$HOME_DIR/config/app.toml"
  sed -i.bak -e 's#^minimum-gas-prices = .*#minimum-gas-prices = "0adydx"#' \
             -e "s#^address = \"localhost:9090\"#address = \"127.0.0.1:$GRPC_PORT\"#" "$A"
  sed -i.bak -e '/^\[grpc-web\]/,/^\[/ s#^enable = true#enable = false#' "$A"
  $BIN config set client chain-id "$CHAIN_ID" --home "$HOME_DIR" >/dev/null 2>&1 || true
  echo "initialised $HOME_DIR ($CHAIN_ID)"
  ;;
start)
  exec $BIN start --home "$HOME_DIR"
  ;;
*) echo "usage: $0 init|start"; exit 2 ;;
esac
