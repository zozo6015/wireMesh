#!/usr/bin/env bash
# spike/tunnel/bench.sh — iperf3 through the boringtun tunnel, plus veth baseline
#
# DEVIATION from the Task 4 brief (documented per Task 3's finding in
# docs/research/boringtun-assessment.md): boringtun's UAPI control socket is
# scoped by *mount* namespace, not network namespace, and lives at a fixed
# path derived only from the interface name (/var/run/wireguard/<ifname>.sock).
# This script's two spike-tunnel instances run via plain `ip netns exec`
# (unlike natlab's tests, they do NOT get private per-namespace mount
# namespaces), so if both sides used the same ifname ("wg0"/"wg0") their UAPI
# sockets would collide in the shared mount namespace exactly as Task 3
# discovered, and `wg set` on one side would silently configure whichever
# device most recently won the bind race. Fix: give each side a distinct
# interface name (wg0 in bwa, wg1 in bwb) — sufficient because ifnames only
# need to be unique per mount namespace, and the wg/addr/up commands are
# already per-namespace.
set -euo pipefail
BIN=${1:?usage: bench.sh <path-to-spike-tunnel-binary>}
cleanup() {
  pkill -f spike-tunnel 2>/dev/null || true
  pkill iperf3 2>/dev/null || true
  ip netns del bwa 2>/dev/null || true
  ip netns del bwb 2>/dev/null || true
}
trap cleanup EXIT; cleanup

ip netns add bwa; ip netns add bwb
ip link add bw0 type veth peer name bw1
ip link set bw0 netns bwa; ip link set bw1 netns bwb
ip netns exec bwa bash -c "ip addr add 10.9.2.1/24 dev bw0; ip link set bw0 up; ip link set lo up"
ip netns exec bwb bash -c "ip addr add 10.9.2.2/24 dev bw1; ip link set bw1 up; ip link set lo up"

echo "== baseline: veth, no tunnel =="
ip netns exec bwb iperf3 -s -D
sleep 1
ip netns exec bwa iperf3 -c 10.9.2.2 -t 10 | tail -4
ip netns exec bwb pkill iperf3

APRIV=$(wg genkey); APUB=$(echo "$APRIV" | wg pubkey)
BPRIV=$(wg genkey); BPUB=$(echo "$BPRIV" | wg pubkey)
ip netns exec bwa "$BIN" wg0 & ip netns exec bwb "$BIN" wg1 &
sleep 1
ip netns exec bwa bash -c "echo $APRIV > /tmp/a.key; wg set wg0 listen-port 51820 private-key /tmp/a.key peer $BPUB allowed-ips 10.10.2.2/32 endpoint 10.9.2.2:51820; ip addr add 10.10.2.1/24 dev wg0; ip link set wg0 up mtu 1280"
ip netns exec bwb bash -c "echo $BPRIV > /tmp/b.key; wg set wg1 listen-port 51820 private-key /tmp/b.key peer $APUB allowed-ips 10.10.2.1/32 endpoint 10.9.2.1:51820; ip addr add 10.10.2.2/24 dev wg1; ip link set wg1 up mtu 1280"

echo "== boringtun tunnel, mtu 1280 =="
ip netns exec bwb iperf3 -s -D
sleep 1
ip netns exec bwa iperf3 -c 10.10.2.2 -t 10 | tail -4
echo "== boringtun tunnel, udp + reverse =="
ip netns exec bwa iperf3 -c 10.10.2.2 -t 10 -R | tail -4
ip netns exec bwb pkill iperf3; pkill -f "$BIN" || true
