# Key-Rotation Make-Before-Break De-Risk Spike — Finding

**Spike:** `spike/keyrot/` (`tests/rotate.rs`, binary `keyrot-dev`).
**Question (linchpin for the key-rotation fast-follow, spec §4.4):** can a gateway
rotate its OWN WireGuard key `Ka → Kb` make-before-break — continuous traffic
flowing, ~ZERO packet loss across the cutover (spec C-5 allows ≤ one handshake
RTT, i.e. ≤ ~1–2 packets)?

**STATUS: PROVEN.** True **zero-drop** (0 packets lost) make-before-break is
feasible — but NOT via a single interface holding two keys as the task brief's
step-3 sketched. It requires **TWO boringtun devices per gateway during the
overlap window**. Measured loss across the cutover: **0 / 90 packets, three
consecutive runs** (`ping -i 0.2 -c 90`, ~18 s flood spanning the whole
rotation).

## The mechanism that worked (mechanism "B" — two devices, one overlay via routing)

WireGuard/boringtun impose two hard constraints that together rule out the
"one interface, two peers, cryptokey routing holds both keys" model:

1. **One private key per interface.** A WireGuard interface has exactly one
   static private key. Serving `Ka` and `Kb` at once therefore needs two
   interfaces (two boringtun `Device`s), full stop.
2. **`allowed-ips` are EXCLUSIVE to one peer per interface.** Even if you add a
   second *peer* entry for `Kb` on the same interface, assigning the overlay
   source `10.20.0.1/32` to it **moves** that allowed-ip off the `Ka` peer
   (WireGuard allowed-ips are a partition, not overlapping routes). The instant
   the allowed-ip moves, inbound packets arriving on the *other* key fail the
   anti-spoof allowed-ips check and are dropped. So a single interface can never
   *simultaneously* accept the overlay IP on both keys — which is exactly what
   zero-drop overlap needs.

The spike therefore runs, on **each** gateway, an OLD device (`Ka`, UDP 51820,
tun `*_o`) and a NEW device (`Kb`, UDP 51821, tun `*_n`) as **separate
processes**, each with its OWN `allowed-ips` namespace. The single overlay
address is kept on `lo` (`10.20.0.1/32` on G_A, `10.20.0.2/32` on G_B) so it is
reachable via *either* tun; the WG `allowed-ips` on each device gate the crypto,
and a plain Linux route (`ip route … dev tun*_{o,n}`) selects which key a given
overlay destination egresses on.

Because BOTH receive paths stay open for the whole overlap, the cutover is just
two **independent local route flips** — no distributed timing coordination, no
window where a sent packet can be rejected:

1. G_A generates `Kb`; brings its NEW device live (`wg set … listen 51821 Kb`).
2. G_B adds a NEW device that peers with `Kb` (its `Ka` device stays up).
3. The `Kb` session is established via an **out-of-band probe pair**
   (`10.20.9.x` on `lo`, routed only over the new tuns) so it does not disturb
   the live flood's route. → **both keys now live simultaneously** (both
   `latest-handshakes > 0` at the same instant; the flood keeps flowing on `Ka`).
4. `ip route replace 10.20.0.2/32 dev tunA_n` on G_A, then the mirror on G_B —
   the flood now rides `Kb`; the still-up OLD receive paths absorb any in-flight
   `Ka` packets.
5. Retire `Ka`: kill both OLD devices (boringtun `DeviceHandle` drop tears down
   the tun). Flow continues on `Kb` — proven by a post-teardown ping with `Ka`
   fully gone (3/3 received).

### Why this is genuinely zero-drop (not just "small drop")

The naive single-interface model can at best hit spec C-5's ≤1–2 packets,
because the two endpoints' cutovers cannot be made atomic across the wire: for a
brief window one side sends on the new key while the other still expects the old
one, and the exclusive `allowed-ips` check drops that window. The two-device
model removes the window entirely — each key's receive path is independently
valid on its own interface throughout the overlap, so the send-side flips can
happen in any order, at any time, with nothing to drop.

## boringtun limitation discovered

- boringtun 0.6 opens its tun internally by name (`TunSocket::new(ifname)`) and
  does **not** set `IFF_MULTI_QUEUE`, so the brief's mechanism "A" (two `Device`s
  sharing ONE tun via a multi-queue fd) is **not available without patching
  boringtun** (a raw-fd / multi-queue `Device` constructor would be needed). It
  was not required: mechanism B with two separate tuns + routing achieves the
  same zero-drop result with **zero boringtun changes** and matches the existing
  per-interface isolation model (`natlab`'s private mount-ns per gateway, see
  `docs/research/boringtun-assessment.md`).
- Minor, non-blocking: boringtun's UAPI reports `latest-handshakes` as a small
  integer rather than a wall-clock unix timestamp (`wg show` renders it as
  "56 years … ago"). Our proof only relies on `> 0` (corroborated by non-zero
  transfer counters and successful pings), so it is unaffected — but it is the
  same handshake-time-semantics quirk already documented in
  `docs/research/cycle4b-path-liveness-note.md`; the real key-rotation code
  should judge session liveness by `rx_bytes` progress, not this field.

## Recommendation for the real §4.4 design

Make-before-break is feasible **as a zero-drop operation**, but the spec's
mental model should be corrected: it is **not** "add the new key as a second
peer on the one interface." The real gateway should, for the rotation window,
**stand up a second WireGuard interface/`Device` bound to a second UDP port with
the new key**, keep the overlay address off the tun (on `lo`/a dummy) so both
interfaces can carry it, and drive the cutover as local route/FIB changes after
the new session has handshaked. Concretely:

1. Controller signals rotation; owner gateway creates NEW device (`Kb`, new
   port), advertises `Kb` + the new endpoint to the peer(s).
2. Each peer stands up a matching NEW device peering with `Kb` (its OLD device
   stays up).
3. New session handshakes (out-of-band / keepalive) — **overlap confirmed by
   `rx_bytes` progress on the new session**, not the handshake-time field.
4. Flip send routes to the new device on both ends (independent, order-free).
5. After a short drain, tear down the OLD devices and free the old port.

Costs/caveats to carry into the design: (a) a **second UDP listen port** is in
use during the overlap (the epoch's punched NAT mapping must be re-opened for
the new port under NAT — key rotation composed with NAT traversal is a separate
concern, deliberately out of this spike's no-NAT scope); (b) the overlay IP must
live on `lo`/dummy, not on the WG tun, so it survives tearing the old tun down;
(c) transient double resource use (2× devices/ports/tuns) for the overlap
duration only. None of these block the zero-drop property, which is the linchpin
this spike set out to establish.

## Reproduce

```
./dev.sh run "cd spike/keyrot && cargo build"
./dev.sh run "cd spike/keyrot && cargo test -- --test-threads=1 --nocapture"
```

Serial, in-container only (tun/netns/boringtun). Result across 3 runs:
`90 transmitted, 90 received, 0 lost` each; both keys proven live during the
overlap; post-teardown flow on `Kb` alone works.
