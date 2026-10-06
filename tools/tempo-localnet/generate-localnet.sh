#!/usr/bin/env bash
# Generate a 3-validator Tempo localnet into ./localnet with the tempo-xtask image.
# The validator IPs match the containers in docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")"
EPOCH_LENGTH="${EPOCH_LENGTH:-100}"
rm -rf localnet
docker run --rm -v "$PWD:/out" ghcr.io/tempoxyz/tempo-xtask@sha256:53ce22a94e9d0c619a5f3d3f948b3d46b772407dad1e0f5487627416e30392f5 generate-localnet \
  -o /out/localnet --accounts 20 --epoch-length "$EPOCH_LENGTH" \
  --validators 172.30.0.11:8000,172.30.0.12:8000,172.30.0.13:8000 --force >/dev/null
for ip in 172.30.0.11 172.30.0.12 172.30.0.13; do
  printf 'tempo-localnet-signing-key-secret\n' > "localnet/$ip:8000/secret.txt"
  chmod 600 "localnet/$ip:8000/secret.txt"
done
echo "localnet generated (epoch length $EPOCH_LENGTH). Start it with: docker compose up -d"
