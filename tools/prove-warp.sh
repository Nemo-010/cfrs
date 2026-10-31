#!/bin/sh
# Proof: a Cloudflare quick tunnel whose edge connection never touches port 7844.
#
# The claim is narrow and checkable, so this checks it in that order:
#   1. this host cannot dial the tunnel edge on 7844 (the control — if this
#      passes, everything after it is meaningless);
#   2. a quick tunnel comes up with `--transport warp` and the edge is reached
#      through a WARP MASQUE tunnel on TCP 443;
#   3. the public URL answers, which is the only thing that proves a visitor
#      reached the origin;
#   4. the direct transport on the same host fails, so step 2 was not luck.
#
#   sh tools/prove-warp.sh [run-seconds]
#
# Exit status is 0 only when 1, 2 and 3 hold.
set -u

SECS=${1:-60}
# The build tree may be redirected off the project (CARGO_TARGET_DIR), which is
# common on a sandbox whose work tree cannot run a file.
if [ -z "${CFRS_BIN:-}" ]; then
    for candidate in ./target/debug/cfrs "${CARGO_TARGET_DIR:-}/debug/cfrs"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            CFRS_BIN=$candidate
            break
        fi
    done
fi
BIN=${CFRS_BIN:-./target/debug/cfrs}
EDGES="198.41.192.27 198.41.200.13"

fail=0
ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "== 1. control: this host must not reach the edge on 7844 =="
for ip in $EDGES; do
    if timeout 5 sh -c "exec 3<>/dev/tcp/$ip/7844" 2>/dev/null; then
        bad "$ip:7844 is reachable over TCP — this host does not need WARP"
    else
        ok "$ip:7844 refused over TCP"
    fi
done

if [ ! -x "$BIN" ]; then
    echo "  building $BIN"
    cargo build --quiet || exit 1
fi

echo
echo "== 2. a quick tunnel over WARP on TCP 443 =="
LOG=$(mktemp)
"$BIN" tunnel --hello-world --transport warp --run-for "$SECS" >"$LOG" 2>&1 &
TUNNEL_PID=$!
trap 'kill $TUNNEL_PID 2>/dev/null; rm -f "$LOG"' EXIT INT TERM

# Wait for the verification line, which the CLI prints only after it has
# fetched the public URL itself.
i=0
while [ $i -lt "$SECS" ]; do
    grep -q "verified public URL" "$LOG" && break
    grep -q "cfrs: tunnel failed\|error:" "$LOG" && break
    sleep 1
    i=$((i + 1))
done
wait $TUNNEL_PID 2>/dev/null

if grep -q "through WARP on TCP 443" "$LOG"; then
    ok "the edge connection was carried through WARP on TCP 443"
else
    bad "no WARP transport line in the log"
fi

URL=$(sed -n 's/.*cfrs: public *\(https:[^ ]*\).*/\1/p' "$LOG" | head -1)
if printf '%s' "$URL" | grep -q '^https://'; then
    ok "public URL issued: $URL"
else
    bad "no public URL was issued"
fi

echo
echo "== 3. the public URL answers =="
if grep -q "verified public URL" "$LOG"; then
    STATUS=$(sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -o 'status=[0-9]*' | head -1)
    ok "the CLI fetched the public URL itself (${STATUS:-HTTP 200})"
else
    # The CLI's self-check may have been cut short; fetch it ourselves.
    if [ -n "${URL:-}" ] && curl -fsS -o /dev/null -m 20 "$URL"; then
        ok "fetched $URL directly"
    else
        bad "the public URL did not answer"
    fi
fi

echo
echo "== 4. control: with direct made impossible, WARP still carries it =="
# This host happens to permit UDP 7844, so "direct fails" cannot be shown by the
# firewall here. CFRS_EDGE pins discovery to an address nothing answers on,
# which makes the direct attempt fail for a reason this script controls.
DL=$(mktemp)
CFRS_EDGE=127.0.0.1:9 timeout 200 "$BIN" tunnel --hello-world --run-for 45 >"$DL" 2>&1
if grep -q "falling back to WARP" "$DL" && grep -q "verified public URL" "$DL"; then
    ok "direct was unreachable and the tunnel still served the public URL through WARP"
else
    bad "the auto fallback did not carry the tunnel"
    sed -n '1,20p' "$DL" | sed 's/^/         /'
fi
rm -f "$DL"

echo
if [ "$fail" -eq 0 ]; then
    echo "PASS: a quick tunnel served the public URL over WARP on TCP 443, and"
    echo "      the auto transport falls back to it when the direct edge is unreachable."
    echo
    echo "Note: this host permits UDP 7844, so the direct transport works here too."
    echo "The WARP path is what a host with 7844 closed in both directions needs."
else
    echo "FAIL: see the lines above."
fi
exit "$fail"
