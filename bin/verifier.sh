#!/bin/bash
# Deploy a verifier against an existing ClprService
# Usage: ./bin/verifier.sh <verifier-type> --rpc-url <url> [--env-file <path>] [--options]

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: ./bin/verifier.sh <hiero|qbft|sei|eth-mainnet|tempo> --rpc-url <url|anvil|besu|hiero> [--env-file <path>] [--options]" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  ./bin/verifier.sh hiero --rpc-url anvil --ledger-id 0x..." >&2
    echo "  ./bin/verifier.sh qbft --rpc-url besu" >&2
    echo "  ./bin/verifier.sh sei --rpc-url anvil" >&2
    echo "  ./bin/verifier.sh eth-mainnet --rpc-url anvil" >&2
    echo "  ./bin/verifier.sh tempo --rpc-url anvil" >&2
    exit 1
fi

VERIFIER_TYPE=$1
shift

# Map verifier type to CLI mode
case "$VERIFIER_TYPE" in
    hiero)
        MODE="hiero-verifier"
        ;;
    qbft)
        MODE="qbft-verifier"
        ;;
    sei)
        MODE="sei-verifier"
        ;;
    eth-mainnet)
        MODE="eth-mainnet-verifier"
        ;;
    tempo)
        MODE="tempo-verifier"
        ;;
    *)
        echo "unknown verifier type: $VERIFIER_TYPE" >&2
        exit 1
        ;;
esac

# Forward all remaining arguments to the CLI
npx tsx script/deploy/cli.ts "$MODE" "$@"
