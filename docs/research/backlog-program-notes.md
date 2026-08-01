# Backlog program — designs and execution state (2026-07-30 → 2026-08-01)

Working notes from the backlog sweep. Designs here are ratified working decisions
(owner may veto); each names its open owner decisions explicitly.

# Backlog program working notes (2026-07-30)

## B5+B7 cutover design: full text lives in the task transcript of the design agent
Key ratified-by-coordinator working decisions (user may veto; surfaced in chat):
1. Separate CutoverProbe oneof (not a PunchDirective flag)
2. Gap budget <=6s per failed attempt; ONE candidate per attempt
3. Cutover cadence 60s exp backoff, give-up after N=5, reset on candidate change/generation bump
4. Generation = random per-boot nonce, "differs" semantics (no persistence)
5. Cutover probes hard-skip during rotation overlap
6. Record spec divergence: endpoint switches DO rekey (remove+re-add+nudge is ratified mechanism)
Proto block: WatchRequest.session_generation=1; ReportRequest.session_generation=7;
PunchDirective.peer_session_generation=4; new SyncMessage oneof CutoverProbe{peer_gateway_id,candidates,go_unix_ms,probe_window_ms,peer_session_generation}
Task order: proto -> (controller gen store/reject + broker cutover sweep) and (gateway EndpointOwner tri-state + roam detect [independently landable post-v0.3.1 as finding-1 fix] -> cutover executor -> generation unsettle override) -> netns cases 2/5/6/7 -> docs.
Netns done-bars: case2 relayed->direct cutover <=90s bounded loss; case5 rollback+give-up (symmetric); case6 roam-wedge regression (healthy relay); case7 restart asymmetry <=30s via generation directive.

## Program state (see TaskList 8-20)
- B1 relay-wedge: impl done, unit green, netns running; then review->CR->PR->v0.3.1
- B2 keepalive mirrors: test author running (worktree fix-sync-keepalive)
- B3 key-rotation plan agent running; B11 operator review agent running
- B4/4b/6 operator round: queued behind B1 netns (build contention); folds B11 findings
- B8 queued behind B2 (relay crate); B9 queued behind B5/B7 proto block
- Production: fabric works via relay+roamed direct; FI sawtooth heals at v0.3.1; gw-home observed endpoint poisoned (10.42.10.1 CNI SNAT) -> B4b observe override

## B11 operator review (DONE 2026-07-30) — ordered fix list for operator round (task #11)
1. CRITICAL relay durability: PVC + identity_persisted mint logic + Recreate strategy (mirror gateway); relay.rs:45 needs_token only, workloads.rs:689 emptyDir, no Recreate at workloads.rs:715-727
2. Roster filter status=="active" at AdminExec::list_gateways boundary (gateway.rs:188/244/284/410; db list_gateways returns all statuses ordered by id)
3. Finalizer best-effort skip when controller CR/pod gone (cleanup_gateway gateway.rs:417, fabric.rs:78-82, admin_exec.rs:100); document teardown order
4. Serialize apply_fabric (tokio::Mutex in Context, list inside critical section) — stale-snapshot segment resurrection (fabric.rs:27-34 vs 75-84)
5. Controller PVC create-only guard (controller.rs:26-29; reuse pvc_needs_create pattern from gateway.rs:59-65)
6. CRD observe/sync endpoint overrides (B4b) + rebind-token on segment CIDR change (B6; note: steady-state failure is silent CIDR non-propagation, deadlock only after identity loss)
7. docs/operator.md rewrite: Limitations says emptyDir identity (WRONG, PVC shipped); says not validated (validated 2026-07-23); CRD table missing storageClass/storageSize; ADD relay non-restartable caveat
8. Status hygiene: WiremeshPolicy status + dangling-ref condition (fabric.rs:45-50 silent drop); stale optional fields never cleared under Patch::Merge (crd.rs:167-171 skip_serializing_if; drain uses stale status.gateway_id gateway.rs:395); mint churn every 15s until enrolled (gateway.rs:327-343)
9. RBAC: missing wiremeshcontrollers/finalizers + wiremeshrelays/finalizers (rbac.yaml:36-40); unused events perm
10. CRD schema: proto enum, cidr/endpoint patterns, port min 1, printer columns
Minors also noted: no backoff (flat 15s), controller singleton unenforced (mod.rs:126-129), exec pod selection readiness (admin_exec.rs:93-100), healthz unconditional, admin_endpoint misnamed

## B3 key-rotation plan (DONE 2026-07-30) — full text in plan-agent transcript
Verified vs main: A open (3 call sites now 1523/2360/2995), B reshaped (observe/report base-port-blind post-rotation; puncher deleted 00bcb32), C open+worse (Rule-4 90s grace-promote with 0 acks black-holes rebooted gw), D open + NEW Role-B lifecycle leak (re-rotation of same peer silently skipped via contains_key main.rs:2735; TunnelSet epoch-number collision; wg0_pins never cleared), E missing (relayed rotation unimplemented in code — pending_peer_configs direct-only).
Task spine (serial): T1 durable promote/retire+boot-active-epoch [SECURITY M] -> T2 non-wedging abort gw+ctrl [M] -> T3 Role-B lifecycle/per-peer keying [M/L] -> T4 A+B active-port threading [L] -> T5 netns cases 3+4 [M]; then T6 relayed rotation [L, needs OD-3] & T7 T9-harness+multi-peer [M] parallel; T8 minors [S] anytime.
Working ODs (coordinator-adopted, user may veto): OD-1 base-port renormalize at boot; OD-2 (a) Report carries live active-epoch pubkey, controller re-rotates on divergence; OD-3 second RelayTransport per overlap pair (B8 multiplexing may subsume); OD-4 grace-promote requires >=1 live ack + real-keyed abort deadline (spec conformance); OD-5 scope rp_filter per-interface if cheap else document.
Execution gate: starts after B1 merges (gateway main.rs overlap).

## B9 X-6 design (DONE) — Candidate A adopted; full text in design-agent transcript
KEY FINDING: schema-2 IR to schema-1 gateway CRASHES the gateway (from_json reject propagates ? through apply_state -> sync loop exit, main.rs:550) — Task 2 makes it non-fatal.
Shape: WatchRequest{1=reserved session_generation(B7), 2=client_version, 3=max_ir_schema}; StateSnapshot{9=controller_version,10=min_supported_version}; GatewayInfo{6,7}; EnrollRequest{6}. Asymmetric: controller rejects only provably-too-old or schema-unconsumable at Watch-open (FailedPrecondition, gateway stays fail-static); apply-time gate inside apply_fabric tx names laggards; enroll-time gate rejects. Legacy: empty->assumed 0.3.x, max_ir_schema 0->1, ages out automatically. Window: fixed one-minor + emergency --min-supported-version lower-only. Persisted gateway.version/max_ir_schema columns (enrolled-not-connected veto; drain = escape hatch). 7 tasks S-L; owner recs 1-7 adopted as working decisions (veto-able). WatchRequest field numbering coordinated with B7.

## B10 hardening audit (DONE) — full text in audit-agent transcript
All 4 carries verified current. UPGRADED: (2) empty-CIDR segment -> nft `{ }` -> apply error -> GATEWAY PROCESS EXIT (main.rs:550 ?; CreateSegment never validates cidrs empty, admin.rs:118-144) — outage class, not cosmetic; (4) 10s REAP_GRACE std::thread::sleep (ebpf.rs:802-810) now blocks Punch/Rotate in same sync loop -> go-skew violation + N-epochs x 10s worst case + metrics/mutex starvation.
PR-A (M): items 1+2+3 — MAX_LPM_CIDRS_PER_SIDE=1024 compile guard (pre-flatten, distinct per side, parity assert enforcer-side) + empty-CIDR reject at CreateSegment/Apply + compile + flatten belt + validate_iface() at probe boundary (<=15B, [A-Za-z0-9_.-], no leading -/.). Files: wiremesh-policy/compile.rs, enforcer nft.rs/ebpf.rs/flatten.rs/lib.rs, controller admin.rs. No gateway main.rs overlap -> parallel-safe with B1/B3.
PR-B (M): item 4 — extract policy-apply worker (latest-wins watch mailbox, spawn_blocking; sync loop publishes not applies; apply errors become log+metric+retry NOT fatal — flag behavior change). Touches gateway main.rs -> serialize after B1 (and coordinate with B3 T4). Owner decisions attached: GENERATIONS=3 or REAP_GRACE reduction (neither required).
Trigger: PR-A test-author when a compile slot frees; PR-B after B1 merge.

## B12 OpenBao scoping (DONE) — full text in scoping-agent transcript
FINDING: audit-actor carry ALREADY FIXED on main (8ddb579, Principal threading, actor_of at admin.rs:73-79, all mutating RPCs) — only regression test missing (task S, red via one-line sabotage demo).
Driver: OpenBaoTrust in wiremesh-trust/src/openbao.rs, KV v2 + PKI engines (spec-settled), token-file or AppRole auth, client-side MIN_TTL, idempotent revoke, serial normalization; CertProfile::serial Some() must be REJECTED (OpenBao can't stamp caller serials) -> forces enrollment reorder: txn-1 token-spend+row -> sign -> txn-2 cert row + compensating mark-failed + orphan sweep [L, riskiest]. issue_server_identity promoted into trait; root-only PKI mount (pem_to_der single-block pin). Env config family WIREMESH_TRUST_PROVIDER=embedded|openbao + WIREMESH_OPENBAO_*. Conformance: real `bao server -dev` child process, feature openbao-conformance, bao binary added to dev/Dockerfile; no test CI exists (container-only, like netns). reqwest rustls-tls-no-provider (ring pin!). Boot fail-fast (DEVIATES from spec cached-start line 198 — owner sign-off), mid-run outage degrades enrollment only. 8 tasks; ODs 1-6 (recs adopted: two-txn ordering, KV2+PKI only, driver unconditional, CRL poll IN, fail-fast deviation, bao >=2.0).

## B8 mux design (DONE) — full text in design-agent transcript
Width bug: registration_key = first 4B SHA-256 hex'd to 8B = 32-bit space; collisions DETERMINISTIC+PERMANENT (loser rejected fail-closed forever, code 3); ~0.07% @n=50, ~17% @n=200. Fix folded into /1 mux protocol (ONE wire break, ALPN wiremesh-relay/1 dual-offer, /0 kept one minor per B9 window): gateway-keyed registry (u64 gid from cert SAN), interest-set authz (consent property preserved — without it /1 is a security regression), 10B header [8B dest_gid][2B channel] (channel = rotation epoch, subsumes B5/B3 OD-3; relay channel-oblivious), NO_ROUTE control datagram replaces per-pair idle death (debounced -> TimedOut semantics, faster than 30s; SM 45s ladder backstop), MTU floor 1322 (/1). Closed on shared conn = relay severed the GATEWAY -> RelayDied fan-out to all attached peers, ONE reconnect (eviction fast-path sharpened). Stale-pin sweep predicate must be re-audited under mux. /0<->/1 cross-bridge translation at the relay (fiddly, explicit test N4). Tasks: R1(M) R2(S) relay-side after B2 merge (parallel with B5); G1(L) G2(M) G3(S) gateway-side after B1+B5; netns N1-N5. ODs A-E recommendations adopted (fold, 10B, interest-authz yes, /0 horizon = B9 skew window, NO_ROUTE include). Sequencing pin: B8 before B3 T6 (relayed rotation built on channels, not throwaway second-pair hack).

## EXECUTION STATE (2026-07-31 morning, post-overnight-stall recovery)
Stall lesson: background bash dies silently when host sleeps — ALL runner commands now foreground + caffeinate -i + -j 1 + per-step reporting.
- B1 (fix-relay-wedge): rounds 1-3 done; authoritative rerun: case3 GREEN 15.1s (Closed fast-path), case4 RED exposed final gap (unsynchronized punch windows + exhausted broker budget + event-driven reports). Round 4 in flight: transition_crosses_settled_boundary helper + gateway prompt-report on settled-boundary transitions (Notify + ~2s debounce) + broker settled→unsettled EDGE → budget reset + emit_pair. Red tests placed (path_settled_boundary.rs compile-red; broker_pathstate +3 cases). Implementer working. Then: full rerun → review delta → CodeRabbit → PR → release.
- B2 (fix-sync-keepalive): impl + review fixes done (validate_host_port shared, consts unified); re-run in batch runner NOW.
- B10 PR-A (fix-hardening-a): implemented; green run in batch runner NOW (incl. conformance 22/22 guard).
- B3-T1 (fix-keyrot-t1): implemented (durable promote/retire, select_boot_key, Role-B active-key catch); runner PENDING (netns key_rotation case) — queue after batches.
- B4 operator round (fix-operator-round): IMPLEMENTED all 6 fixes (relay PVC+Recreate+mint gating via availability heuristic; active_in_segment filter; cleanup_should_skip; fabric_apply_lock; shared pvc_needs_create; observe/sync overrides + needs_rebind/token_secret_body/bound_cidrs_of + rebind_segment_id threaded both transports; crdgen regenerated; docs/operator.md rewritten). Runner PENDING. Reviewer flag: relay identity_persisted = Deployment-availability heuristic.
- B12-T1 (fix-audit-actor-test): DONE (red-proof + green); needs runner confirm + PR.
- Release order: first-green merges first; every merge = release (minor for proto/CRD-surface changes, patch otherwise).
