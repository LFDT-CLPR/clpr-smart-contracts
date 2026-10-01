#!/usr/bin/env bash
# Re-records a fixture in test/e2e/fixtures/rootstock-live/ from a real RSKj regtest node:
#   regtest.json     (default)     a CLPR Channel record for the anvil spec and the forge tests
#   compliance.json  (compliance)  one service, one state per endpoint manifest, for RootstockComplianceTest
#   RSKJ_JAR=/path/rskj-core-<ver>-all.jar test/e2e/relay/rootstock/refresh-regtest.sh [regtest|compliance]
# The fat jar ships in the rsksmart/rskj Docker image (/var/lib/rsk). Needs a JDK ≥ 17 (the dumper is a
# single-file Java program). The node runs with V0 headers (RSKIP144/351/535 off), as on mainnet.
set -euo pipefail
: "${RSKJ_JAR:?set RSKJ_JAR to the rskj-core-*-all.jar}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
WORK="$(mktemp -d)"
PORT="${RSK_REGTEST_PORT:-4454}"
cat > "$WORK/node.conf" <<CONF
database.dir = $WORK/db
rpc.providers.web.http.port = $PORT
rpc.modules.rsk.enabled = true
rpc.modules.rsk.version = "1.0"
peer.port = $((PORT + 46057))
blockchain.config.consensusRules.rskip144 = -1
blockchain.config.consensusRules.rskip351 = -1
blockchain.config.consensusRules.rskip535 = -1
CONF
(cd "$WORK" && exec java -Xmx768m -Drsk.conf.file="$WORK/node.conf" -cp "$RSKJ_JAR" co.rsk.Start --regtest > "$WORK/node.log" 2>&1) &
NODE=$!
trap 'kill $NODE 2>/dev/null || true' EXIT
for _ in $(seq 1 90); do
  curl -sf -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "http://127.0.0.1:$PORT" >/dev/null && break
  sleep 1
done
cd "$ROOT"
MODE="${1:-regtest}"
npx tsx test/e2e/relay/buildRootstockProof.ts "--capture-$MODE" --rpc "http://127.0.0.1:$PORT"
kill -TERM $NODE; wait $NODE || true   # graceful stop flushes the trie store
java -cp "$RSKJ_JAR" "$HERE/UnitrieDump.java" "$WORK/db/unitrie" "$WORK/unitrie-dump.txt"
npx tsx test/e2e/relay/buildRootstockProof.ts "--proofs-$MODE" --dump "$WORK/unitrie-dump.txt"
rm -rf "$WORK"
