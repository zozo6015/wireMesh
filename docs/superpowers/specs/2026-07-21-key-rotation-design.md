# WireMesh — Key-Rotation Design (fast-follow)

> **Fast-follow deferred from Cycle 4a.** Authority: master engineering design
> `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` §4.4 — **with the
> §4.4 mechanism CORRECTED by the de-risk spike (see §1).** Builds on merged Cycle 4
> (4a direct gateway, 4b NAT punch + path SM, 4c relay). Controller-side epoch
> bookkeeping already exists (cycles 2/3 + 4a); this cycle delivers the gateway
> data-plane rotation and the promote/retire state machine.

## 0. Scope

Per-gateway per-epoch WireGuard key rotation with **make-before-break** (zero-drop)
cutover, triggered on-demand (`fabricctl key rotate <gateway>`) or by a 30-day timer.
Private keys are generated **locally on the rotating gateway** and never leave it
(master §4.4 / D5); only public keys transit the controller. Rotation reuses the
existing 4b punch / 4c relay path machinery to make the new key's port reachable
before cutover, so it works for direct AND relayed gateways.

## 1. De-risk finding — the §4.4 mechanism is CORRECTED

The linchpin was de-risked first (`spike/keyrot`, netns, **0/90 packets lost across
3 runs**; see `docs/research/keyrot-spike-note.md`). It **disproved** master §4.4's
stated mechanism and established the working one:

- **§4.4 said (WRONG):** add the new key `Kb` as a *second peer on the same WG
  interface* and let cryptokey routing hold both epochs. **Impossible:** WireGuard
  treats `allowed-ips` as *exclusive to one peer per interface*, so assigning the
  overlay `/32` to the `Kb` peer *moves* it off the `Ka` peer; inbound on the other
  key then fails the anti-spoof check.
- **Working mechanism (B):** during the overlap, run **two boringtun `Device`s** —
  OLD (`Ka`, its own UDP port + tun) and NEW (`Kb`, a second UDP port + tun), each
  with its own `allowed-ips` namespace. Keep the **overlay IP on `lo`/dummy** (not on
  a tun) so it is reachable via either tun and survives tearing the old one. Establish
  the `Kb` session, then cut over with **independent `ip route replace` flips on both
  ends** (both receive paths stay open the whole overlap → no rejection window), then
  drain and tear down the OLD Device.
- **boringtun 0.6 limitation:** it opens its tun internally by name with no
  `IFF_MULTI_QUEUE`/raw-fd `Device` constructor, so "two Devices sharing one tun"
  would require patching boringtun — and is **not needed** (mechanism B avoids it).
- **NAT caveat (this cycle's real work):** the `Kb` Device listens on a NEW UDP port,
  which for a gateway behind NAT must be made reachable *before* cutover. This cycle
  runs the new port through the existing 4b punch / 4c relay path SM.

## 2. Done bar

netns conformance (`wiremesh-testkit`, `--features netns-tests`, mandatory `tc netem`
where NAT/punch is involved), generalizing the spike harness:
1. **Direct rotation, zero drop** — a directly-reachable pair; rotate one gateway's
   key under a continuous ping flood; assert **~0 packet loss** (≤ one handshake RTT,
   per C-5) across the cutover; old epoch retired, new epoch `active`.
2. **Relayed rotation, zero drop** — a symmetric-NAT pair whose path is `Relayed`
   (4c); rotate under load; the new port establishes its relay path before cutover;
   assert ~0 drop; old epoch retired.
3. **Failure is non-destructive** — if the new session never handshakes within the
   grace window, the old epoch stays `active` (no drop, no data-plane change) and the
   controller retries; assert traffic never dropped and epoch `n` still serves.
4. **Persistence / crash-safety** — the epoch state machine survives a controller
   restart mid-rotation (resumes from the `gateway_key` DB snapshot) and a gateway
   restart (multi-epoch keys persisted in `state.json`, fail-static).

## 3. Rotation flow (make-before-break)

1. **Trigger:** `Admin.RotateKey(gateway_id)` (from `fabricctl key rotate`) OR the
   controller's 30-day timer. Controller opens a `gateway_key` row `(gateway_id,
   n+1, state='pending')` — but with **no real pubkey yet** (today's placeholder is
   removed) — bumps revision, audits, and issues a **`RotateDirective`** to the
   rotating gateway's open `Sync.Watch` stream (addressed to that gateway, like a
   `PunchDirective`).
2. **Gateway mints + stands up (make):** on `RotateDirective(epoch=n+1)` the gateway
   generates a fresh X25519 keypair `Kb`, persists it to `state.json` as a pending
   epoch, and brings up a **second boringtun `Device`** on a NEW UDP port with `Kb`.
   The overlay IP is held on `lo`/dummy (migrated off the tun) so both Devices reach
   it. The gateway **submits `Kb`'s public key** back to the controller
   (`SubmitEpochKey`, gateway→controller — the real-key channel `rotate_key` lacked).
3. **Controller advertises:** it records `Kb` as the epoch-`n+1` pubkey (`pending`),
   and pushes a peer `Delta` carrying the rotating gateway's full key set (`Ka`
   active + `Kb` pending) AND the new-port candidate — **preserving each peer's
   existing candidate list** (fixes the current `KeyRotated`-delta clobber, §4).
4. **Peers establish the new path:** each peer of the rotating gateway stands up its
   own **transient second Device** (its OWN unchanged key + the rotating gateway's
   `Kb` as the peer), and drives the new port through the existing **path SM** (4b
   punch / 4c relay) until the `Kb` session handshakes. (Peers also cannot hold two
   of the rotating gateway's keys on one interface — same anti-spoof constraint.)
5. **Cutover:** once `Kb` handshakes (real handshake + `rx` corroboration, per the
   4b path-liveness note), both ends `ip route replace` the overlay route onto the
   `Kb` interface — order-free, both receive paths open → ~0 drop. Each peer sets a
   **per-epoch ack** in `Report` (`Kb` session live).
6. **Promote / retire (break):** when peers have acked (or a grace timeout elapses
   with the session healthy), the controller promotes `n+1→active`, moves `n→retiring`
   then deletes it, and pushes the reduced key set; both ends tear down the OLD
   Device + free the old port. **Non-destructive on failure:** if acks don't arrive
   and `Kb` isn't healthy, the controller leaves `n` active everywhere, tears down the
   unused `Kb` Devices, and retries later — no traffic impact.

## 4. Proto surface (`proto/wiremesh/v1/*.proto`)

- **`RotateDirective`** — new `SyncMessage.body` variant (controller→gateway), like
  `PunchDirective`: `{ uint32 epoch; }` — tells the addressed gateway to generate +
  stand up epoch `n+1` and submit its pubkey. Routed to that gateway's stream only.
- **`SubmitEpochKey`** — a dedicated gateway→controller `Sync` RPC
  `SubmitEpochKey(SubmitEpochKeyRequest{ uint32 epoch; string pubkey; })` (chosen
  over piggybacking `Report` so submission is prompt, not gated on the next periodic
  Report tick): the rotating gateway posts its real epoch-`n+1` public key right
  after generating it. Controller updates the `pending` row's pubkey (sentinel →
  real) and re-advertises. mTLS-authenticated like every other Sync call; the
  controller verifies the caller's cert CN matches the gateway whose epoch it is.
- **Per-epoch ack** — additive `ReportRequest` field `repeated EpochAck { uint64
  peer_gateway_id; uint32 epoch; bool live; }`: a peer reports that the rotating
  gateway's epoch-`n+1` session is handshaked + live, driving promote/retire.
- **Fix (pre-existing bug):** `delta_for_change(KeyRotated)` currently emits
  `candidate_endpoints: Vec::new()`, clobbering a peer's 4b/4c candidate list on the
  gateway. The rotation delta MUST preserve candidates (carry the peer's real
  candidate set, mirroring the `EndpointObserved`/snapshot builders).
- `PeerKey{epoch,pubkey,state}` and `Peer.keys` (already a list) are unchanged —
  they already carry multiple simultaneous epochs on the wire.

## 5. Controller

- **Real key material:** `Db::rotate_key` stops minting the `placeholder-pubkey-…`
  string; it creates the `pending` row with an explicit sentinel pubkey
  `awaiting-submission` (keeps the `pubkey NOT NULL` schema valid), which
  `SubmitEpochKey` overwrites with the real key. The Sync **projection does NOT
  advertise a pending epoch whose pubkey is still the sentinel** — peers only ever
  see a `pending` `PeerKey` once its real key has been submitted, so the peer path
  SM never acts on a keyless epoch.
- **Promote/retire state machine (NEW — none exists today):** driven by the
  per-epoch acks with a grace-timeout fallback. Transitions `pending→active` (on
  quorum ack / healthy session) and `active(old)→retiring→deleted`. Persisted in
  `gateway_key.state` so a controller crash mid-rotation resumes from the DB.
  Emits `KeyRotated` deltas at each transition (with preserved candidates).
- **30-day timer:** a controller background task that issues `RotateKey` per gateway
  on the configured interval (default 30d, configurable via `Config`). Idempotent
  with in-flight rotations (skip a gateway already mid-rotation).
- Audit every transition; keep the existing single-use/atomicity + revision-bump
  discipline; read `(keys, revision)` consistently (mirror the 4c `relays_snapshot`
  atomic-read fix so a rotation delta can't carry a stale key set at a newer revision).

## 6. Gateway

- **Own-epoch key generation + persistence:** on `RotateDirective`, generate an
  X25519 keypair; persist `state.json` as a multi-epoch structure (`epochs: [{epoch,
  private_key_b64, pubkey_b64, state}]`) — fail-static, 0600. `Identity`'s single
  `wg_private_key_b64` becomes the epoch-0 entry (back-compat migration on load).
- **Second-Device lifecycle:** a `TunnelSet`/`EpochTunnel` manager that can hold >1
  boringtun `Device` (each its own port + tun), bring one up on rotate and tear one
  down on retire. Overlay IP migrates from the tun to `lo`/dummy at boot (a change
  from 4a's tun-holds-IP), so both epoch tuns route to it.
- **Peer multi-key handling:** when a peer's advertised key set has a `pending`
  epoch, stand up a transient second Device for that peer's new key and reconcile it;
  on the peer becoming `active`-only again, tear the old one down. `PeerState` retains
  the full `keys: Vec<PeerKey>` (not just `active_pubkey_b64`) — the current
  discard-all-but-active behavior is the core data-plane gap to close.
- **New-port path establishment:** the `Kb` Device's port is driven through the
  existing 4b/4c path SM (punch or relay) exactly like a normal endpoint, so it's
  reachable before cutover — direct and relayed both work.
- **Cutover:** on a confirmed `Kb` handshake (real handshake + rx corroboration),
  `ip route replace` the overlay onto the `Kb` tun on both ends; report the `EpochAck`.
- **Rekey-free note:** this IS a rekey (a new WG key) — but make-before-break means
  the DATA FLOW never drops; the old session serves until the new one is proven live.

## 7. Decisions (owner-ratified)

- **A. Spec §4.4 mechanism corrected to "two Devices per gateway during overlap,
  overlay IP on `lo`, route-flip cutover"** (de-risk finding). The master spec §4.4
  should be amended to match; this design is authoritative for rotation until then.
- **B. Reuse the 4b/4c path machinery** for the new port's reachability (direct +
  relay both supported in v1). Owner decision.
- **C. Ack-driven promote/retire with a grace-timeout fallback** (not pure timer) —
  precise + non-destructive on failure, matching §4.4's "peer acks → retire."
- **D. On-demand + 30-day timer trigger.** Timer included in v1 (small, and it's the
  operational point of rotation); skip gateways already mid-rotation.

## 8. Non-goals (this fast-follow)

Per-pair keys (D5 keeps per-gateway); rotating multiple gateways simultaneously
(serialize / queue); patching boringtun for shared-tun (mechanism B avoids it);
key escrow / HSM (OpenBao is Cycle 2b); IPv6; re-keying the mTLS control-plane cert
(that's the certificate lifecycle, separate). The relay's OWN key rotation reuses the
same gateway mechanism (a relay is a gateway-kind identity) but its conformance case
is a follow-up if it doesn't fall out of the mesh case for free.

## 9. Task decomposition (for the plan)

1. Proto: `RotateDirective`, `SubmitEpochKey` (or `ReportRequest.epoch_key`),
   `ReportRequest.epoch_acks`; round-trip tests. + fix `KeyRotated` candidate clobber.
2. Controller: real key material (drop placeholder; `SubmitEpochKey` fills the pending
   row) + advertise-when-real.
3. Controller: promote/retire state machine (ack-driven + grace timeout, persisted) +
   atomic `(keys, revision)` read; tests (promote on ack, retire, non-destructive on
   no-ack, survives restart).
4. Controller: 30-day timer (skip in-flight); test.
5. Gateway: multi-epoch key gen + `state.json` persistence + epoch-0 migration; unit.
6. Gateway: `EpochTunnel`/second-Device lifecycle + overlay-IP-on-`lo`; unit + a
   focused loopback/netns bring-up-two-devices test.
7. Gateway: peer multi-key handling (`PeerState.keys`, transient second Device per
   rotating peer, reconcile).
8. Gateway: `RotateDirective` handling + `SubmitEpochKey` + new-port path via the SM +
   route-flip cutover + `EpochAck` reporting (driver wiring).
9. testkit: generalize the `spike/keyrot` rotation-under-load harness into
   `wiremesh-testkit` (direct + symmetric/relay topologies).
10. netns done-bar (§2 cases 1–4) + docs (research note + amend master §4.4 + CLAUDE.md).

## 10. Reference

De-risk spike + finding: `spike/keyrot/`, `docs/research/keyrot-spike-note.md`.
Reuses: 4b `PunchDirective`/broker/path SM, 4c relay + `relays_snapshot` atomic-read
pattern, 4a fail-static `state.json`, the `EndpointObserved` candidate-preservation
precedent.
