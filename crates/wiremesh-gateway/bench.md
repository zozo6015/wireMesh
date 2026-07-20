# Gateway throughput bench (G-2 gate)

The engineering spec's G-2 acceptance criterion is **>=1 Gbps single-tunnel
throughput on a 4-vCPU cloud VM** (non-virtualized/non-oversubscribed CPU).
This number **cannot** be measured meaningfully inside the macOS
Docker-Desktop/linuxkit dev container — see the Phase-0 Bet-1 finding in
`docs/research/phase0-results.md` (a receive-side delivery cap around
~7.5–7.8 Mbit/s was measured there, environment-confounded, not
representative of real hardware). `tests/throughput_bench.rs` in this crate
is a **smoke test only**: it proves iperf3 runs end-to-end across a real
`wiremesh-gateway` tunnel and prints the number, but it deliberately does
**not** assert a floor. Treat any Mbit/s figure from the netns harness as
harness-only, never as evidence for or against G-2.

## Running the smoke test (any environment, informational only)

```
./dev.sh run "cargo test -p wiremesh-gateway --test throughput_bench \
  --features netns-tests -- --test-threads=1 --nocapture"
```

Prints a line like `THROUGHPUT SMOKE (netns, harness-only, NOT the G-2
gate): N.NN Mbit/s` to stdout. Skips (does not fail) if `iperf3` is absent
from the container.

## Running the real G-2 measurement on a 4-vCPU cloud VM

1. Provision a 4-vCPU VM on a real cloud provider with non-oversubscribed
   CPU (dedicated/non-burstable instance type — e.g. not a "burstable" t-class
   on AWS). Two such VMs (or two network namespaces on one VM connected by a
   real veth/bridge, if you want a single-host approximation) are needed to
   host the two gateway ends.
2. Build the release binary:
   ```
   cargo build --release -p wiremesh-gateway
   ```
3. Stand up two `wiremesh-gateway` processes against a running
   `wiremesh-controller` (or reuse the exact netns topology from
   `crates/wiremesh-gateway/tests/mesh_milestone.rs` as a template — swap the
   in-container `Lab` netns for real hosts/interfaces), so both ends have a
   live WireGuard tunnel with policy permitting the iperf3 port.
4. Run iperf3 **with parallel streams**, matching the spec's 8-tunnel
   aggregate methodology used for the PRD's G-2 acceptance:
   ```
   # on the receiving gateway's segment:
   iperf3 -s

   # on the sending gateway's segment:
   iperf3 -c <receiver-overlay-ip> -t 30 -P 4
   ```
5. Also capture the UDP loss profile, to settle whether the container-only
   receive-cap finding was environment noise or a real boringtun bottleneck:
   ```
   iperf3 -c <receiver-overlay-ip> -u -b 0 -t 10
   # inspect the Lost/Total datagrams column, not just the reported Mbit/s
   ```
6. Record the result — sender/receiver Mbit/s, retransmits (TCP run) and
   Lost/Total datagrams (UDP run), VM instance type/vCPU count/provider,
   kernel version — in `docs/research/phase0-results.md` under the "Cycle
   4a — G-2 throughput" section, replacing "pending" with the measured
   numbers and a go/no-go call against the >=1 Gbps floor.

## Notes

- The bench harness historically used `pkill -f iperf3` globally
  (`spike/tunnel/bench.sh`); scope any process cleanup to this job's own PIDs
  before running on a shared cloud host (carried Phase-0 finding, see
  `docs/progress.html` open risks).
- Tunnel MTU is fixed at 1280 (spec G-8); this bounds per-packet overhead
  and is why parallel streams (`-P 4`) rather than a single stream better
  approximate the sustained-throughput target real deployments care about.
