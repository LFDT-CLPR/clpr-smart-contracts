#!/usr/bin/env sh
# Start a local Canton sandbox (Daml SDK / dpm 3.5.12 from Digital Asset's official installer) in a
# Docker container and build the CLPR Daml app. The JSON Ledger API is published on
# 127.0.0.1:${CANTON_JSON_PORT:-17575}. damlc ships x86_64-only for macOS, so everything runs in a
# linux/arm64 (or amd64) JDK container.
#
#   test/e2e/backend/canton/start-canton.sh          # start (idempotent)
#   test/e2e/backend/canton/start-canton.sh stop     # remove the container (keeps the dpm cache volume)
set -eu
NAME=${CANTON_CONTAINER:-clpr-canton}
PORT=${CANTON_JSON_PORT:-17575}
SDK=${DPM_SDK_VERSION:-3.5.12}
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)

if [ "${1:-}" = "stop" ]; then docker rm -f "$NAME"; exit 0; fi

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker run -d --name "$NAME" --cpus 3 -m 8g \
    -v "$ROOT":/work -v clpr-canton-dpm:/root/.dpm \
    -p 127.0.0.1:"$PORT":7575 eclipse-temurin:17-jdk sleep infinity
fi

docker exec "$NAME" sh -c "[ -x /root/.dpm/bin/dpm ] || (curl -sSL https://get.digitalasset.com/install/install.sh -o /tmp/i.sh && TERM=dumb sh /tmp/i.sh $SDK)"
docker exec -w /work/daml/clpr "$NAME" sh -c 'PATH=/root/.dpm/bin:$PATH dpm build --all'

if ! curl -sf "http://127.0.0.1:$PORT/v2/version" >/dev/null; then
  docker exec -d "$NAME" sh -c 'cd /tmp && PATH=/root/.dpm/bin:$PATH JAVA_OPTS="-Xmx3g" dpm sandbox --no-tty \
    -C canton.participants.sandbox.http-ledger-api.port=7575,canton.participants.sandbox.http-ledger-api.address=0.0.0.0 \
    > /tmp/sandbox.log 2>&1'
  i=0; until curl -sf "http://127.0.0.1:$PORT/v2/version" >/dev/null; do
    i=$((i+1)); [ $i -gt 100 ] && { docker exec "$NAME" tail -40 /tmp/sandbox.log; exit 1; }; sleep 3; done
fi
echo "Canton JSON Ledger API: http://127.0.0.1:$PORT ($(curl -s http://127.0.0.1:$PORT/v2/version | head -c 40)...)"
