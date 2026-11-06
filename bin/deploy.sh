#!/usr/bin/env bash
# CLPR deployment wrapper. Drives the viem deploy CLI (script/deploy/cli.ts) against
# selectable scopes (all / modules / service / config). Parses the broadcast
# receipt after each run and prints and/or writes deployed addresses to JSON.
#
# Usage:
#   bin/deploy.sh                         # interactive menu
#   bin/deploy.sh <mode> [--rpc <alias>]  # non-interactive
#
# Modes: all | modules | service | config | e2e-with-hiero-verifier |
#        hiero-verifier | qbft-verifier | sei-verifier | eth-mainnet-verifier |
#        tempo-verifier
#
# Required env vars per mode:
#   all      → PRIVATE_KEY  (INITIAL_OWNER optional; defaults to deployer)
#   modules  → PRIVATE_KEY
#   service  → PRIVATE_KEY, CHANNEL_LOGIC, MESSAGING_LOGIC,
#              CONNECTOR_LOGIC, ADMIN_LOGIC, BUNDLE_DECODE_HELPER
#              (service mode also verifies that those addresses have deployed
#               bytecode on the target RPC before constructing ClprService)
#   config   → PRIVATE_KEY, CLPR_SERVICE
#   hiero-verifier   → PRIVATE_KEY, CLPR_SERVICE (optional: LEDGER_ID)
#   qbft-verifier    → PRIVATE_KEY, CLPR_SERVICE
#   sei-verifier     → PRIVATE_KEY, CLPR_SERVICE
#   eth-mainnet-verifier → PRIVATE_KEY, CLPR_SERVICE
#   tempo-verifier   → PRIVATE_KEY, CLPR_SERVICE
#
# Besu backend (--rpc besu): the two-node compose stack is auto-managed.
#   - If besu-a-1 / besu-b-1 are not running, `npm run e2e:up` is invoked.
#   - Container ports (8545 → random host port) are resolved at runtime and
#     persisted to .env as BESU_RPC_A / BESU_RPC_B; $RPC is set to the chosen
#     node's URL.
#   - Pick the target with `BESU_NODE=a` (default, chainId 1337) or `BESU_NODE=b`
#     (chainId 1338).
#   - Teardown is not automatic; `npm run e2e:down` when done.
#
# Exit codes: 0 ok, 2 usage, 3 missing env, 4 missing forge/anvil/docker/npm,
#             5 missing jq, 6 service mode invoked with un-deployed module addresses.

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$'\033[1m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    CYAN=$'\033[36m'
    RESET=$'\033[0m'
else
    BOLD=''; RED=''; GREEN=''; YELLOW=''; CYAN=''; RESET=''
fi

err()  { echo "${RED}error:${RESET} $*" >&2; }
warn() { echo "${YELLOW}warn:${RESET} $*" >&2; }
info() { echo "${CYAN}info:${RESET} $*" >&2; }
ok()   { echo "${GREEN}ok:${RESET} $*" >&2; }

# ── Locate repo root ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

DEPLOYED_ENV_FILE="$REPO_ROOT/.env"

# Auto-source .env so a prior `modules` run feeds the next `service` run.
if [ -f "$DEPLOYED_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set -a; . "$DEPLOYED_ENV_FILE"; set +a
    info "loaded $DEPLOYED_ENV_FILE"
fi

# ── Args ──────────────────────────────────────────────────────────────
MODE="${1:-}"
RPC=""
RPC_EXPLICIT=0
if [ -n "$MODE" ] && [[ "$MODE" != -* ]]; then
    shift
else
    MODE=""
fi
while [ $# -gt 0 ]; do
    case "$1" in
        --rpc) shift; RPC="${1:-}"; RPC_EXPLICIT=1; [ -z "$RPC" ] && { err "--rpc needs an alias"; exit 2; } ;;
        --rpc=*) RPC="${1#--rpc=}"; RPC_EXPLICIT=1 ;;
        -h|--help)
            sed -n '/^# CLPR/,/^set -/p' "$0" | sed -n '/^#/p' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) err "unexpected arg: $1"; exit 2 ;;
    esac
    shift || true
done

# ── Backend menu (interactive) ────────────────────────────────────────
# Only runs when the operator didn't pass --rpc. Sets RPC to an alias defined
# in foundry.toml ("anvil" or "besu"); operator can also enter a custom alias
# or full URL via the prompt.
prompt_backend() {
    echo "${BOLD}Select a target backend:${RESET}" >&2
    echo "  1) anvil (local dev chain)" >&2
    echo "  2) besu (local/staging Besu node)" >&2
    echo "  3) custom (enter rpc alias or URL)" >&2
    echo "  4) quit" >&2

    read -r -p "${BOLD}> ${RESET}" choice

    case "$choice" in
        1) RPC="anvil"; return ;;
        2) RPC="besu";  return ;;
        3)
            read -r -p "rpc alias or URL: " RPC
            if [ -z "$RPC" ]; then
                err "empty rpc"
                prompt_backend
                return
            fi
            return
            ;;
        4|q|Q) info "aborted"; exit 0 ;;
        *) err "invalid choice"; prompt_backend; return ;;
    esac
}

if [ "$RPC_EXPLICIT" = 0 ]; then
    if [ -t 0 ]; then
        prompt_backend
    else
        # Preserve previous non-interactive default so CI keeps working.
        RPC="anvil"
    fi
fi

# ── Mode menu (interactive) ───────────────────────────────────────────
prompt_mode() {
    echo "${BOLD}Select a deployment mode:${RESET}" >&2
    PS3="${BOLD}> ${RESET}"
    local choice
    select choice in "all (modules + service + config)" \
                     "modules (4 logic + bundleDecodeHelper)" \
                     "service (ClprService only; reuses module addrs)" \
                     "config (apply initial ledger + economic config)" \
                     "e2e-with-hiero-verifier (CLPR + HieroVerifier + e2e harness)" \
                     "hiero-verifier (deploy Hiero stack against existing ClprService)" \
                     "qbft-verifier (deploy QBFT verifier against existing ClprService)" \
                     "sei-verifier (deploy Sei/CometBFT verifier against existing ClprService)" \
                     "eth-mainnet-verifier (deploy Ethereum mainnet verifier against existing ClprService)" \
                     "tempo-verifier (deploy Tempo verifier against existing ClprService)" \
                     "quit"; do
        case "$REPLY" in
            1) MODE="all"; return ;;
            2) MODE="modules"; return ;;
            3) MODE="service"; return ;;
            4) MODE="config"; return ;;
            5) MODE="e2e-with-hiero-verifier"; return ;;
            6) MODE="hiero-verifier"; return ;;
            7) MODE="qbft-verifier"; return ;;
            8) MODE="sei-verifier"; return ;;
            9) MODE="eth-mainnet-verifier"; return ;;
            10) MODE="tempo-verifier"; return ;;
            11|q|Q) info "aborted"; exit 0 ;;
            *) err "invalid choice" ;;
        esac
    done
}

if [ -z "$MODE" ]; then
    if [ ! -t 0 ]; then
        err "no mode given and stdin is not a tty — refusing to run silently."
        err "pass a mode: all | modules | service | config | e2e-with-hiero-verifier | hiero-verifier | qbft-verifier | sei-verifier | eth-mainnet-verifier | tempo-verifier"
        exit 2
    fi
    prompt_mode
fi

case "$MODE" in
    all|modules|service|config|e2e-with-hiero-verifier|hiero-verifier|qbft-verifier|sei-verifier|eth-mainnet-verifier|tempo-verifier) ;;
    *) err "unknown mode: $MODE"; err "valid: all | modules | service | config | e2e-with-hiero-verifier | hiero-verifier | qbft-verifier | sei-verifier | eth-mainnet-verifier | tempo-verifier"; exit 2 ;;
esac

# ── Env validation per mode ───────────────────────────────────────────
require_env() {
    local missing=()
    for v in "$@"; do
        if [ -z "${!v:-}" ]; then missing+=("$v"); fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "missing required env vars for mode '$MODE':"
        for v in "${missing[@]}"; do echo "  - $v" >&2; done
        echo "" >&2
        echo "Set them in your shell, in .env" >&2
        echo "See README.md → Deployment for details." >&2
        exit 3
    fi
}

case "$MODE" in
    all)
        require_env PRIVATE_KEY
        ;;
    modules)
        require_env PRIVATE_KEY
        ;;
    service)
        require_env PRIVATE_KEY \
            CHANNEL_LOGIC MESSAGING_LOGIC BUNDLE_LOGIC CONNECTOR_LOGIC ADMIN_LOGIC BUNDLE_DECODE_HELPER
        ;;
    config)
        require_env PRIVATE_KEY CLPR_SERVICE
        ;;
    e2e-with-hiero-verifier)
        require_env PRIVATE_KEY
        ;;
esac

info "mode=$MODE rpc=$RPC"

if ! command -v npx >/dev/null 2>&1; then
    err "npx not found in PATH (install Node.js)"
    exit 4
fi

# ── Modules-before-service guard ──────────────────────────────────────
# For `service` mode, the 5 module env vars are required (checked above), but
# they're just addresses — the addresses might point at nothing if `modules`
# was never run on this RPC. Verify each has bytecode before we deploy a
# ClprService that would silently delegatecall into the void.
#
# Note: precomputing module addresses (CREATE2 / deterministic factory) would
# let modules + service be deployed in any order. Tracked as a follow-up — see
# README "Deployment ordering" section.
verify_modules_have_code() {
    [ "$MODE" = "service" ] || return 0
    local v addr code missing=()
    for v in CHANNEL_LOGIC MESSAGING_LOGIC BUNDLE_LOGIC CONNECTOR_LOGIC ADMIN_LOGIC BUNDLE_DECODE_HELPER; do
        addr="${!v}"
        # cast auto-resolves the rpc alias via foundry.toml.
        code=$(cast code "$addr" --rpc-url "$RPC" 2>/dev/null || true)
        if [ -z "$code" ] || [ "$code" = "0x" ]; then
            missing+=("$v=$addr")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "the following module addresses have no deployed bytecode on '$RPC':"
        for m in "${missing[@]}"; do echo "  - $m" >&2; done
        echo "" >&2
        echo "Deploy the modules first:" >&2
        echo "  ./bin/deploy.sh modules --rpc $RPC" >&2
        exit 6
    fi
}

# ── Besu compose lifecycle + preflight (when RPC alias is 'besu') ─────
# Mirrors test/e2e/backend/BesuDriver.ts:
#   1. ensure docker is on PATH
#   2. check `docker ps` for the besu-a-1 / besu-b-1 containers
#   3. if either is missing, run `npm run e2e:up`
#   4. resolve each container's dynamic host port via `docker port`
#   5. poll eth_chainId until both nodes answer (waitReady equivalent)
#   6. verify chainId matches genesis (1337 for A, 1338 for B)
#   7. persist BESU_RPC_A / BESU_RPC_B to .env
#   8. set $RPC to the chosen node's URL (default: A; override via BESU_NODE=b)
#   9. verify deployer balance > 0 on the chosen node
#
# Why we rewrite $RPC: docker compose maps :8545 to a random host port each
# run, so we can't pin a static `besu` alias in foundry.toml — forge accepts
# a full URL via --rpc-url instead.
BESU_NODE="${BESU_NODE:-a}"

# Append-or-replace KEY=value in $DEPLOYED_ENV_FILE. Used for BESU_RPC_* so a
# follow-up `bin/deploy.sh service` re-uses the same compose ports without
# re-resolving them.
upsert_env_var() {
    local key="$1" val="$2"
    local file="$DEPLOYED_ENV_FILE"
    if [ -f "$file" ] && grep -qE "^${key}=" "$file"; then
        local tmp="$file.tmp.$$"
        awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k {$0=k"="v} {print}' "$file" > "$tmp"
        mv "$tmp" "$file"
    else
        echo "${key}=${val}" >> "$file"
    fi
    export "$key=$val"
}

# Poll eth_chainId on $1 until it returns $2, or fail after 60s. Mirrors
# BesuDriver.waitReady — a TCP-accept check (testcontainers' default) is not
# enough; Besu's JSON-RPC isn't ready the instant the socket binds.
wait_for_chain_id() {
    local url="$1" expected="$2"
    local deadline=$(( $(date +%s) + 60 ))
    local chain
    while [ "$(date +%s)" -lt "$deadline" ]; do
        chain=$(cast chain-id --rpc-url "$url" 2>/dev/null || true)
        if [ -n "$chain" ] && [ "$chain" != "0" ]; then
            if [ "$chain" = "$expected" ]; then
                return 0
            fi
            err "besu at $url reports chainId $chain, expected $expected"
            err "wrong container mapped — refusing to broadcast"
            exit 4
        fi
        sleep 1
    done
    err "besu at $url did not become ready (eth_chainId) within 60s"
    exit 4
}

ensure_besu_ready() {
    [ "$RPC" = "besu" ] || return 0
    if ! command -v docker >/dev/null 2>&1; then
        err "docker not in PATH — needed to drive the besu compose stack"
        exit 4
    fi
    if ! command -v cast >/dev/null 2>&1; then
        err "cast not in PATH (install foundry)"
        exit 4
    fi
    if ! command -v npm >/dev/null 2>&1; then
        err "npm not in PATH — needed to invoke 'npm run e2e:up'"
        exit 4
    fi

    # Use `docker compose ps` against the compose file (resolves containers
    # by service name regardless of project prefix; compose v2 prepends the
    # parent dir name, so the raw containers are `backend-besu-a-1` etc).
    local compose_file="test/e2e/backend/docker-compose.yml"
    local id_a id_b
    id_a=$(docker compose -f "$compose_file" ps -q besu-a 2>/dev/null)
    id_b=$(docker compose -f "$compose_file" ps -q besu-b 2>/dev/null)
    if [ -z "$id_a" ] || [ -z "$id_b" ]; then
        info "besu containers not running — starting via 'npm run e2e:up'"
        if ! npm run e2e:up 1>&2; then
            err "'npm run e2e:up' failed"
            exit 4
        fi
        id_a=$(docker compose -f "$compose_file" ps -q besu-a 2>/dev/null)
        id_b=$(docker compose -f "$compose_file" ps -q besu-b 2>/dev/null)
    else
        info "besu containers already running"
    fi
    if [ -z "$id_a" ] || [ -z "$id_b" ]; then
        err "besu containers still not found after e2e:up"
        err "debug: docker compose -f $compose_file ps"
        exit 4
    fi

    # `docker port <id> 8545` prints lines like "0.0.0.0:54321" or
    # "[::]:54321"; take the last colon-separated field to get the port.
    local port_a port_b
    port_a=$(docker port "$id_a" 8545 2>/dev/null | head -1 | awk -F: '{print $NF}')
    port_b=$(docker port "$id_b" 8545 2>/dev/null | head -1 | awk -F: '{print $NF}')
    if [ -z "$port_a" ] || [ -z "$port_b" ]; then
        err "could not resolve host port for besu-a / besu-b (container ids $id_a / $id_b)"
        err "debug: docker port $id_a 8545"
        exit 4
    fi
    BESU_RPC_A="http://localhost:$port_a"
    BESU_RPC_B="http://localhost:$port_b"
    info "besu-a → $BESU_RPC_A  besu-b → $BESU_RPC_B"

    info "waiting for eth_chainId on both nodes..."
    wait_for_chain_id "$BESU_RPC_A" 1337
    wait_for_chain_id "$BESU_RPC_B" 1338
    ok "besu nodes ready (chainIds 1337, 1338)"

    upsert_env_var BESU_RPC_A "$BESU_RPC_A"
    upsert_env_var BESU_RPC_B "$BESU_RPC_B"

    case "$BESU_NODE" in
        a|A) RPC="$BESU_RPC_A" ;;
        b|B) RPC="$BESU_RPC_B" ;;
        *) err "BESU_NODE must be 'a' or 'b' (got: $BESU_NODE)"; exit 2 ;;
    esac
    info "deploying against besu-$BESU_NODE at $RPC"

    local deployer balance
    deployer=$(cast wallet address --private-key "$PRIVATE_KEY" 2>/dev/null || true)
    if [ -z "$deployer" ]; then
        err "could not derive deployer address from PRIVATE_KEY"
        exit 3
    fi
    balance=$(cast balance "$deployer" --rpc-url "$RPC" 2>/dev/null || echo "0")
    if [ -z "$balance" ] || [ "$balance" = "0" ]; then
        err "deployer $deployer has zero balance on besu-$BESU_NODE"
        err "prefund it in test/e2e/backend/genesis-${BESU_NODE}.json and re-up the stack"
        exit 3
    fi
    info "deployer $deployer has balance $balance wei"
    ok "besu preflight passed"
}

# ── Anvil auto-start (only when --rpc anvil) ──────────────────────────
# The `anvil` alias in foundry.toml points at http://127.0.0.1:8545. If nothing
# is listening there we start anvil in the background and wait until the RPC
# answers. We do NOT kill anvil on exit — the user (or a follow-up wrapper
# invocation) may want to query state with `cast`; the printed PID makes
# cleanup explicit.
ANVIL_DEFAULT_URL="http://127.0.0.1:8545"
ensure_anvil_running() {
    [ "$RPC" = "anvil" ] || return 0
    if cast block-number --rpc-url "$ANVIL_DEFAULT_URL" >/dev/null 2>&1; then
        info "anvil already running at $ANVIL_DEFAULT_URL"
        return 0
    fi
    if ! command -v anvil >/dev/null 2>&1; then
        err "anvil not in PATH (install foundry)"
        exit 4
    fi
    info "no anvil at $ANVIL_DEFAULT_URL — starting one in the background"
    # Detach so anvil survives this script's exit and isn't killed by the shell
    # tearing down our process group.
    nohup anvil --silent >/dev/null 2>&1 &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if cast block-number --rpc-url "$ANVIL_DEFAULT_URL" >/dev/null 2>&1; then
            ok "anvil started (pid $pid). kill with: kill $pid"
            return 0
        fi
        sleep 1
    done
    err "anvil failed to come up within 15s"
    kill "$pid" 2>/dev/null || true
    exit 4
}
ensure_anvil_running
ensure_besu_ready

# After anvil (or whichever rpc) is up, verify module bytecode for service mode.
verify_modules_have_code

# viem deploy CLI — stderr is human output, stdout is the JSON result.
echo "" >&2
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
info "Deployment starting" >&2
info "  mode:   $MODE" >&2
info "  rpc:    $RPC" >&2
info "  chain:  $(cast chain-id --rpc-url "$RPC" 2>/dev/null || echo 'unknown')" >&2
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
echo "" >&2

DEPLOY_ARGS=("$MODE" "--rpc-url" "$RPC")
# Node >=20.6 has its own native --env-file flag that intercepts this argument
# before cli.ts ever runs, and errors out if the path doesn't exist. Only pass
# it when the file is actually there; cli.ts's own default already points at
# the same path otherwise.
[ -f "$DEPLOYED_ENV_FILE" ] && DEPLOY_ARGS+=("--env-file" "$DEPLOYED_ENV_FILE")

if ! npx tsx script/deploy/cli.ts "${DEPLOY_ARGS[@]}"; then
    err "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    err "Deployment FAILED" >&2
    err "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    exit 1
fi
echo "" >&2
ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
ok "Deployment completed successfully" >&2
ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
echo "" >&2
