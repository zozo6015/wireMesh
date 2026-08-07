# The macOS-gateway exclusion was traded against a Kubernetes story that does not exist

**Written:** 2026-08-05, after verifying the live deployment and the operator source.
**Status:** a correction to the decision record. Proposes no code change by itself.

## The decision as it stands

The gateway is Linux-only, in two ratified places:

- `docs/PRD.md` **Non-Goals item 5**: *"Windows/BSD gateway hosts (v1) — Linux-only gateways.
  Workloads behind gateways can be any OS since they're untouched."*
- `docs/superpowers/specs/2026-07-22-release-distribution-design.md` §0:
  *"Component scope: macOS = fabricctl + controller + relay"* … *"The gateway stays
  Linux-only (eBPF/tun)"*, with `wiremesh-gateway` marked ❌ for both macOS columns in
  the component table (§ table, line 60), and the reason stated at lines 53-54: it loads
  eBPF (tc/BPF), creates a tun, and programs nftables/routes.

`docs/PRD.md` requirement **X-1** lists the supported gateway platforms — AWS, GCP, Azure, Proxmox,
generic Linux VPS/bare metal, Kubernetes, local Linux workstation/PC. No macOS entry.

**The technical reason is sound and is not in question.** A macOS gateway would need a
third enforcer backend on `pf`, behaviourally equivalent to eBPF and nftables, proven
against a conformance suite that only runs in Linux netns. That is the expensive part, and
it is why the exclusion exists.

## The premise it was traded against

The exclusion was accepted on the understanding that **Kubernetes plus the operator would
cover the case end-to-end**, so no macOS gateway would be needed. That premise does not
hold as built. Verified 2026-08-05 against the live fabric and the operator source:

- **No HA.** The gateway's identity lives in a per-gateway **RWO node-local PVC**, and
  `crates/wiremesh-operator/src/workloads.rs:455-471` states outright that cross-node
  failover is out of scope precisely because of it. Node loss = segment down until the
  node returns. On a cluster with a node autoscaler this is worse than a single box: the
  node can be reclaimed at any time and the pod cannot reschedule, because the PVC is
  bound to a node that no longer exists.
- **Not zero-config.** A gateway fronting a network requires that network to route to it.
  The home segment had no return route, so replies from `10.0.125.11` went to the LAN
  router (`via 10.0.125.1`) instead of gw-home at `10.0.125.12` and were dropped.
  Symptom is asymmetric and misleading — the sending gateway's tx counter increments
  perfectly while rx stays flat at zero, which reads as a tunnel fault. **This affects
  inbound as much as outbound**, so remote access into the segment reaches only the
  gateway node itself.
- **The operator cannot express what operators need.** It hardcodes the controller's env
  list with no CRD field for `WIREMESH_ROTATION_INTERVAL` (`controller_deployment`,
  `workloads.rs`). Since the control plane moved to px it also cannot perform fabric admin
  at all — its admin channel was a kubectl-exec into a controller pod that no longer exists
  in that cluster.

  > **CORRECTED 2026-08-07.** This originally continued "…and force-applies the Deployment
  > (`controllers/mod.rs:207-208`), so hand-edits revert on the next reconcile." **Both
  > halves are wrong.** The cited lines are the *generic* `apply()`, not
  > `apply_deployment()`, which is what the Deployment actually goes through. And the
  > conclusion does not follow: a container's `env` is a server-side-apply **list-map keyed
  > by `name`**, so `.force()` only overrides keys present in the applier's own body. The
  > operator never names `WIREMESH_ROTATION_INTERVAL`, so a value set by `kubectl set env`
  > is not in its ownership set and **survives every reconcile**. Verified against a live
  > cluster's OpenAPI v3 schema (`env` → `x-kubernetes-list-type: map`).
  >
  > What IS force-clobbered, checked in the same pass: container **`args`** are
  > `x-kubernetes-list-type: atomic`, so any hand-added flag is wiped on the next reconcile
  > and there is no CRD surface for extra flags; and **`replicas: Some(1)`** is force-set on
  > all three workloads, so `kubectl scale --replicas=0` is reverted *immediately* (each
  > reconciler `.owns(Deployment)`, so the scale event re-enqueues rather than waiting out
  > the requeue). See task #33.
  >
  > The trap this creates for the obvious fix: adding `WIREMESH_ROTATION_INTERVAL` to the
  > hardcoded list with a default would make the operator **own** the key, at which point
  > `.force()` really would overwrite a human's `off` with the default — silently
  > re-enabling rotation on exactly the clusters that had mitigated it. Emit the key only
  > when the CRD field is `Some`.

To be fair to the record: the operator *does* deploy a working gateway, and pinning is
supported — `WiremeshGatewaySpec` has `node_name` and `node_selector` (`crd.rs:144`),
folded into a `kubernetes.io/hostname` selector so a `WaitForFirstConsumer` PVC still
binds. Pinning makes placement **deterministic**. It does not make it **available**.

## Reversing the exclusion is NOT the remedy

The obvious correction — "then ship a macOS gateway" — does not deliver what the premise
promised, and this is the load-bearing point of this note.

**A gateway fronting a network requires that network to route to it. That is inherent to
"no agents on workloads" (`PRD.md`, Guiding Principle 2), not to Linux.** Put the gateway on a Mac and:

- the LAN still needs the same static routes, in both directions;
- the Mac becomes the same single point of failure the k8s node was;
- if it is a laptop, it additionally cannot sleep, change networks, or leave the building,
  because it is the L3 path for its whole segment;
- and you have paid for a `pf` enforcer backend to get there.

So the exclusion was accepted for a reason that did not hold, **and** the reversal would
not fix the thing the reason was about. Both halves need saying, or the next reader
"corrects" the record by building the expensive wrong thing.

## What the requirement actually needs

The unmet requirement is *a Mac joins the fabric, reaches the segments, no routing changes
anywhere, toggled on and off like any VPN client*. That is a **client/agent** — a peer that
joins **for itself only**, does not front a network, and does not forward.

A client needs no enforcer **in the direction it initiates**. The gateway's enforcer
attaches to its own tun (`GatewayEnforcer::attach(&cfg.tun_ifname)`,
`crates/wiremesh-gateway/src/main.rs:493`), so `client → segment` traffic is matched on
tun **ingress** at the receiving gateway and correctly policed with no new mechanism. The
`pf` backend that blocks a macOS *gateway* is therefore not on the critical path for a
macOS *client*.

> **CORRECTION (verified 2026-08-05, after this note's first draft).** The first draft
> claimed policy is applied at the gateway "either way". That is **wrong in the receive
> direction.** Enforcement is *ingress-on-tun only* — `aeth_egress` unconditionally returns
> `TC_ACT_PIPE` (`crates/wiremesh-enforcer-ebpf/program/src/main.rs:418-420`), and the nft
> backend hooks only `iifname "<iface>"` (`nft.rs:103,107`). So **`segment → client` is
> policed by nothing**: the sending gateway's egress never drops, and the client has no
> enforcer. Every *existing* peer is protected because every existing peer runs an enforcer
> on its own tun; a client would be the first peer in the fabric that nothing protects.
> This is an owner decision, not a detail — see the client scoping note.

**This IS a reversal of a ratified decision, and the first draft was wrong to say
otherwise.** `docs/PRD.md` **Non-Goals item 1** lists as an explicit v1 non-goal: *"Device/user-level access
(v1) — no per-laptop, per-user client. This is segment-to-segment routing… conflating the
two would bloat v1."* The macOS *gateway* exclusion (Non-Goals item 5) and the *client* exclusion (item 1)
are two separate ratified decisions, and a client component reopens the second one. It
needed a spec amendment in the engineering design's §11, not just a scoping note — **that
landed 2026-08-05 as §11.8**, together with PRD G-4a.

## What should change in the record

All four were applied on 2026-08-05:

1. **Annotate the macOS-gateway exclusion** in `PRD.md` Non-Goals item 5 to state that it
   was traded against a Kubernetes HA story that does not exist as built — while keeping
   the exclusion, which stands on the `pf`-enforcer cost. ✅
2. **Correct the release-distribution spec's macOS scope.** Its §0 reads
   *"macOS = fabricctl + controller + relay"*, which is true of *components that exist*
   but now misleads: with a client in scope, macOS carries **per-device connectivity**, not
   just admin. Annotated so nobody reads it as "macOS cannot do data plane" — it means
   macOS cannot host a *gateway*. ✅
3. **Assign the "workstation joins the fabric" requirement to the client component** and
   record it in the engineering design's **§11 amendments** (item 8), which is the
   authority the PRD defers to. Doing it only in `docs/research/` would have left the
   top-authority document contradicting the decision. ✅
4. **Amend `PRD.md` G-4.** This one was not in the original list and is the easiest to
   miss: G-4's acceptance criterion is *"traffic matching no allow rule is dropped and
   counted"*, which a client destination violates. A new **G-4a** records the carve-out
   explicitly rather than letting the Non-Goals amendment silently contradict a
   G-requirement. ✅

No claim that Kubernetes gives the gateway HA was found in the shipped docs — the
assumption lived in conversation, not in the record, which is precisely why it survived.

## What is NOT claimed here

- That the gateway should become non-Linux. It should not; the enforcer reasoning stands.
- That "one gateway per segment" is wrong. That is a separate design question — a single
  L3 path per segment is inherent to no-agents. What is *not* inherent is that gateway
  being stuck to one node's disk.
- That Kubernetes is the wrong platform. The gateway's own storage and pinning model
  disables k8s's HA mechanisms; that is a WireMesh property, not a Kubernetes one.

See the companion scoping note for the client component, and
`rotation-endpoint-and-port-model-is-broken.md` for the unrelated rotation work that is
currently the reason automatic key rotation is disabled fabric-wide.
