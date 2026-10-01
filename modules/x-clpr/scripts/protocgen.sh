#!/usr/bin/env sh
# Regenerates x/clpr/types/*.pb.go. Run from modules/x-clpr:
#   docker run --rm -v "$PWD":/workspace -w /workspace ghcr.io/cosmos/proto-builder:0.14.0 sh ./scripts/protocgen.sh
set -eu
cd proto
buf mod update
buf generate --template buf.gen.gogo.yaml
cd ..
cp -r github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types/* x/clpr/types/
rm -rf github.com
