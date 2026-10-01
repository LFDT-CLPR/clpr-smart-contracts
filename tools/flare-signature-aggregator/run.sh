#!/usr/bin/env bash
# Run Ava Labs' signature-aggregator (ava-labs/icm-services) against a Flare network, for
# `npm run flare-live:refresh`. It needs no node of our own: it reads peer IPs from the public
# info.peers API, dials the validators over avalanchego p2p (TLS staking handshake with an ephemeral
# cert, port 9651) and sends them ACP-118 signature requests.
#
#   tools/flare-signature-aggregator/run.sh coston2   # API on :18480
#   tools/flare-signature-aggregator/run.sh flare     # API on :18483 (+ weight proxy on :18482)
#
# Built from icm-services commit bd47aec (avalanchego v1.15.0; needs Go 1.26.7):
#   git clone --depth 1 https://github.com/ava-labs/icm-services && cd icm-services
#   GOTOOLCHAIN=go1.26.7 go build -o bin/signature-aggregator ./signature-aggregator/main
# Set SIG_AGG to the binary path.
#
# Flare mainnet: avalanchego v1.15 parses P-Chain weights as uint64, and Flare's total stake
# (~2.2e19 nFLR) overflows it (go-flare uses big.Int). weight-proxy.mjs divides P-Chain weights by 16
# for the aggregator only. That changes only when the aggregator stops collecting; the capture
# re-checks the aggregate against the exact weights.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="${SIG_AGG:-signature-aggregator}"
tmp="$(mktemp -d)"
case "${1:-}" in
  coston2)
    api=https://coston2-api.flare.network
    cat > "$tmp/c.json" <<J
{"log-level":"info","info-api":{"base-url":"$api"},"p-chain-api":{"base-url":"$api"},"api-port":18480,"metrics-port":18481}
J
    ;;
  flare)
    api=https://flare-api.flare.network
    node "$here/weight-proxy.mjs" "$api" 18482 16 &
    trap 'kill $! 2>/dev/null' EXIT
    cat > "$tmp/c.json" <<J
{"log-level":"info","info-api":{"base-url":"$api"},"p-chain-api":{"base-url":"http://127.0.0.1:18482"},"api-port":18483,"metrics-port":18484}
J
    ;;
  *) echo "usage: $0 coston2|flare" >&2; exit 2 ;;
esac
"$bin" --config-file "$tmp/c.json"
