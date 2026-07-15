#!/usr/bin/env bash
# dev/doctor.sh — verify the container/kernel can run every spike
set -u
pass=0; fail=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "PASS $1"; ((pass++)); else echo "FAIL $1"; ((fail++)); fi; }

chk "kernel >= 5.10"        '[ "$(uname -r | cut -d. -f1)" -ge 6 ] || { [ "$(uname -r | cut -d. -f1)" -eq 5 ] && [ "$(uname -r | cut -d. -f2)" -ge 10 ]; }'
chk "netns create/delete"   'ip netns add __doc && ip netns del __doc'
chk "tun device"            'ip tuntap add __doc0 mode tun && ip link del __doc0'
chk "clsact qdisc"          'ip link add __docv0 type veth peer name __docv1 && tc qdisc add dev __docv0 clsact && ip link del __docv0'
chk "bpf prog load (sched_cls)" 'bpftool feature probe kernel | grep -q "program_type sched_cls is available"'
chk "nftables"              'nft add table inet __doc && nft delete table inet __doc'
chk "wireguard-tools (wg)"  'wg --version'
chk "iperf3"                'iperf3 --version'
echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
