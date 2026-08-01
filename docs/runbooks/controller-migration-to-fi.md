# Runbook — moving the controller from zolab (k8s) to aether-prod-fi-01

**Goal.** Relocate the WireMesh control plane from the in-cluster deployment on zolab
to the bare-metal host `aether-prod-fi-01` (`95.217.118.177`), so that endpoint
observation happens from **outside** every NAT'd gateway's boundary.

**Why.** Observation only yields a usable candidate when the observer sits outside the
NAT it is observing. With the controller inside zolab's LAN, gw-home's probe never
crosses its router, so the controller records an internal address
(`10.42.10.1` via kube-proxy SNAT, or `10.0.125.1` via the router's hairpin) and every
peer punches at something unroutable. From FI, gw-home's probe traverses its router and
the controller records the real public mapping. Measured 2026-08-01: the zolab router
preserves port 51820 in hairpin, which suggests endpoint-independent mapping — so
gw-home has a genuine chance of reaching `direct` rather than staying relayed.

**Blast radius.** Gateways are fail-static: they keep forwarding on their last applied
state with the controller absent. So control-plane downtime does **not** drop traffic.
What stalls during the window: enrollment, policy changes, punch brokering, relay
health/eviction, and key rotation.

**Estimated window.** 30–45 minutes, with a rollback point that restores the old
controller in under 5.

---

## 0. Facts this runbook assumes (verify before starting)

| Thing | Value |
|---|---|
| New controller host | `aether-prod-fi-01`, public `95.217.118.177` |
| Gateways | `5` = FI (segment `aether`, 10.0.0.0/24) · `6` = px (`206.83.146.32`) · `9` = gw-home (segment `home`, 10.0.125.0/24) |
| Segments | `aether`, `aether-dev`, `aws`, `home` |
| Ports | 9400 enroll (TCP/TLS) · 9500 sync (TCP/mTLS) · 9600 observe (UDP) · 9443 admin (**loopback only, always**) |
| State to move | `/var/lib/wiremesh` — CA key/cert **and** the SQLite DB |
| Current controller | k8s Deployment `wiremesh-controller` in ns `wiremesh` on zolab |
| Version to install | v0.4.0 (must be ≥ the gateways' version) |

> **The CA is the crown jewel.** Every gateway's identity chains to it and every
> enrollment token is pinned to its fingerprint. If the CA does not survive the move,
> all three gateways must re-enroll from scratch. Treat `/var/lib/wiremesh` as the
> single artifact whose integrity decides success.

---

## 1. Pre-flight (no changes yet)

```bash
# 1.1 — On FI: confirm the ports are free and the host can bind them.
ss -lntup | grep -E ':(9400|9500|9600|9443)\b' || echo "ports free"

# 1.2 — On FI: confirm the gateway is healthy BEFORE we touch anything.
systemctl is-active wiremesh-gateway
journalctl -u wiremesh-gateway -n 20 --no-pager

# 1.3 — On zolab: record the current fabric so we can diff afterwards.
kubectl -n wiremesh exec deploy/wiremesh-controller -c admin-exec -- \
  kubectl -n wiremesh exec deploy/wiremesh-controller -c controller -- \
  wiremesh-controller --version
kubectl -n wiremesh get pods,svc

# 1.4 — Capture the CA fingerprint. It MUST be identical after the move.
#      (Any gateway's on-disk CA bundle works; FI's is easiest.)
openssl x509 -in /var/lib/wiremesh/ca.pem -noout -fingerprint -sha256
```

Record the fingerprint from 1.4. It is the migration's correctness check.

---

## 2. Rollback point — back up the control-plane state

Do this **before** stopping anything.

```bash
# 2.1 — On zolab: snapshot the controller's PVC contents to a tarball.
POD=$(kubectl -n wiremesh get pod -l app.kubernetes.io/instance=wiremesh-controller \
        -o jsonpath='{.items[0].metadata.name}')
kubectl -n wiremesh exec "$POD" -c controller -- tar -C /var/lib/wiremesh -cf - . \
  > wiremesh-controller-state-$(date +%Y%m%d-%H%M).tar

# 2.2 — Verify the tarball is sane and contains the CA + DB.
tar -tvf wiremesh-controller-state-*.tar | head -20
```

Expect at minimum: `ca.pem`, the CA private key, and the SQLite DB (plus its `-wal`/`-shm`
if present — those matter, take them).

> **Consistency note.** SQLite in WAL mode can be mid-write. Safest is to scale the
> controller to 0 replicas *first* (step 3.1), then snapshot from the PVC via a
> throwaway pod. If you take the snapshot hot (as above), re-take it after the scale-down
> and use the second one — the cold copy is authoritative.

**Rollback at any point before step 6:** scale the zolab controller back to 1
(`kubectl -n wiremesh scale deploy/wiremesh-controller --replicas=1`) and revert the
gateway configs. Nothing else is destroyed until step 8.

---

## 3. Quiesce the old controller

```bash
# 3.1 — On zolab: stop the controller (gateways go fail-static; traffic continues).
kubectl -n wiremesh scale deploy/wiremesh-controller --replicas=0
kubectl -n wiremesh get pods

# 3.2 — Cold snapshot from the PVC (authoritative copy).
#       Mount the PVC in a throwaway pod and tar it out.
kubectl -n wiremesh run pvc-dump --rm -i --restart=Never --image=busybox \
  --overrides='{"spec":{"containers":[{"name":"c","image":"busybox","command":["tar","-C","/data","-cf","-","."],"volumeMounts":[{"name":"d","mountPath":"/data"}]}],"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"wiremesh-controller-data"}}]}}' \
  > wiremesh-controller-state-cold.tar
tar -tvf wiremesh-controller-state-cold.tar | head
```

(Confirm the PVC name first: `kubectl -n wiremesh get pvc`.)

---

## 4. Install and seed the controller on FI

```bash
# 4.1 — On FI: install the controller package (v0.4.0), matching the gateway's version.
curl -fsSLO https://github.com/zozo6015/wireMesh/releases/download/v0.4.0/wiremesh-controller_0.4.0_amd64.deb
sha256sum -c <(grep 'wiremesh-controller_0.4.0_amd64.deb' SHA256SUMS)   # fetch SHA256SUMS too
dpkg -i wiremesh-controller_0.4.0_amd64.deb

# 4.2 — Do NOT start it yet. Seed the state first.
systemctl stop wiremesh-controller 2>/dev/null || true

# 4.3 — Restore the cold snapshot into the data dir.
install -d -o wiremesh -g wiremesh -m 0700 /var/lib/wiremesh
tar -C /var/lib/wiremesh -xf wiremesh-controller-state-cold.tar
chown -R wiremesh:wiremesh /var/lib/wiremesh
find /var/lib/wiremesh -type f -exec chmod 0600 {} \;

# 4.4 — CRITICAL: the CA fingerprint must match step 1.4 exactly.
openssl x509 -in /var/lib/wiremesh/ca.pem -noout -fingerprint -sha256
```

**If the fingerprint differs, stop.** Something restored the wrong data or the controller
generated a fresh CA. Do not proceed — re-check the tarball.

```bash
# 4.5 — Configure. The shipped template already sets what we need.
cat /etc/wiremesh/controller.env
#   WIREMESH_DATA_DIR=/var/lib/wiremesh
#   WIREMESH_BIND_IP=0.0.0.0      <- required so remote gateways can reach it
# Admin TCP stays loopback-only regardless of BIND_IP — by design, do not try to change it.

# 4.6 — Open the firewall for the three public planes (admin stays closed).
ufw allow 9400/tcp comment 'wiremesh enroll'
ufw allow 9500/tcp comment 'wiremesh sync'
ufw allow 9600/udp comment 'wiremesh observe'
# Explicitly do NOT open 9443.

# 4.7 — Start.
systemctl enable --now wiremesh-controller
journalctl -u wiremesh-controller -n 30 --no-pager
```

Expect a listening line of the shape:
`tcp=0.0.0.0:9400 sync_tcp=0.0.0.0:9500 uds=/run/wiremesh/controller.sock admin_tcp=127.0.0.1:9443 observe_udp=0.0.0.0:9600`

```bash
# 4.8 — Sanity: the roster survived the move (all three gateways, unchanged ids).
fabricctl --socket /run/wiremesh/controller.sock gateway list
```

Expect ids **5, 6, 9** with their existing segments. If the roster is empty, the DB did
not restore — go back to 4.3.

---

## 5. Reachability check from outside, before touching the gateways

```bash
# From px (or any external host):
nc -vz 95.217.118.177 9400
nc -vz 95.217.118.177 9500
# UDP has no handshake; verify by watching the controller receive the probe in step 6.
```

Both TCP checks must succeed before continuing. If they don't, fix the firewall/routing
now — with the gateways still pointed at the old (stopped) controller, you are still in
the fail-static window and nothing is broken.

---

## 6. Re-point the gateways (one at a time, verify each)

Order matters: **px first** (external, lowest risk), then **FI**, then **gw-home** (the
one whose observation we are fixing).

### 6.1 px

```bash
# On px:
sed -i 's/^WIREMESH_GATEWAY_CONTROLLER_SYNC=.*/WIREMESH_GATEWAY_CONTROLLER_SYNC=95.217.118.177:9500/' /etc/wiremesh/gateway.env
sed -i 's/^WIREMESH_GATEWAY_OBSERVE=.*/WIREMESH_GATEWAY_OBSERVE=95.217.118.177:9600/' /etc/wiremesh/gateway.env
# (Check the actual key names in /etc/wiremesh/gateway.env first — adjust if they differ.)
systemctl restart wiremesh-gateway
journalctl -u wiremesh-gateway -f
```

Verify: no `controller unreachable`, and an `observed endpoint 206.83.146.32:51820`
line appears (public address, port preserved).

### 6.2 FI (the controller's own host)

```bash
# On FI. Use the PUBLIC address, not 127.0.0.1 — sending to loopback would make the
# controller observe 127.0.0.1 as this gateway's candidate, which is useless to peers.
sed -i 's/^WIREMESH_GATEWAY_CONTROLLER_SYNC=.*/WIREMESH_GATEWAY_CONTROLLER_SYNC=95.217.118.177:9500/' /etc/wiremesh/gateway.env
sed -i 's/^WIREMESH_GATEWAY_OBSERVE=.*/WIREMESH_GATEWAY_OBSERVE=95.217.118.177:9600/' /etc/wiremesh/gateway.env
systemctl restart wiremesh-gateway
journalctl -u wiremesh-gateway -f
```

Verify `observed endpoint 95.217.118.177:51820`.

### 6.3 gw-home (the payoff)

```bash
# On the workstation, against zolab:
kubectl patch wiremeshgateways gw-home --type=merge \
  -p '{"spec":{"observeEndpoint":"95.217.118.177:9600","syncEndpoint":"95.217.118.177:9500"}}'
kubectl -n wiremesh rollout status deploy/gw-home
kubectl -n wiremesh logs deploy/gw-home -f
```

**This is the check the whole migration exists for:**

```
observed endpoint 79.119.133.77:<port>     <- public NAT mapping, NOT 10.x
```

If it still shows a `10.x` address, the probe is not leaving the LAN — investigate
routing before declaring success.

---

## 7. Verify the fabric converges

```bash
# 7.1 — On FI: all three gateways connected and reporting.
fabricctl --socket /run/wiremesh/controller.sock gateway list

# 7.2 — Path states. The goal is `direct` for pairs whose NATs allow it.
journalctl -u wiremesh-gateway -n 100 --no-pager | grep -E 'path peer|punch confirmed'

# 7.3 — Data plane: ping across segments (aether <-> home).
ping -c 3 10.0.125.<a workload in home>
```

Success looks like: punch directives while converging, `path peer=N connecting -> direct`
for the punchable pairs, then a quiet log with only `observed endpoint` heartbeats.
gw-home may still land on `relay` if its NAT turns out to be symmetric — that is a
legitimate outcome, not a failure of the migration; the candidate is now *real* either way.

---

## 8. Decommission the zolab control plane (only after 7 passes)

Leave this until the fabric has been healthy for a while — an hour is sensible.

```bash
# 8.1 — Remove the in-cluster controller workload.
kubectl -n wiremesh delete deploy/wiremesh-controller
kubectl -n wiremesh delete svc/wiremesh-controller svc/wiremesh-controller-observe

# 8.2 — Remove the now-pointless exposure plumbing.
#       (Envoy TCP-passthrough listeners for 9400/9500 and the observe LoadBalancer.)
#       Check what references them first:
kubectl get gateway,tcproute,udproute -A | grep -i wiremesh

# 8.3 — KEEP the PVC until you are certain. It is the rollback.
kubectl -n wiremesh get pvc
```

> Do **not** delete the `WiremeshController` CR before the Deployment, or the operator's
> finalizer path and the workload GC will race. Delete the workload explicitly as above,
> then the CR if you want the operator to stop managing it at all.

---

## 9. Operator admin transport (do this or accept the limitation)

The operator currently reaches the Admin API by exec'ing into the controller pod's
sidecar. With the controller off-cluster that path is gone, and Admin TCP binds
**loopback-only on FI** — it is not reachable from the cluster by design.

Two workable options:

- **A. Manage the fabric from FI with `fabricctl`** (simplest). Segment/policy/token
  operations run on the controller host over the UDS. The operator keeps reconciling
  gw-home's *workload* but can no longer perform admin RPCs — expect its
  `cleanup_should_skip` path to warn and skip drains, which v0.4.0 handles deliberately.
- **B. Tunnel the Admin port** to the cluster and set `WIREMESH_ADMIN_ADDR` on the
  operator (its gRPC transport is supported and v0.4.0 handles gRPC-mode cleanup
  correctly). Requires an SSH tunnel or equivalent from a cluster node to
  `127.0.0.1:9443` on FI, plus the admin bearer token.

Option A is recommended unless you actively want CR-driven fabric management.

---

## 10. Post-migration follow-ups

- **Update the deployment docs** (`docs/operator.md`, the exposure README) — the Envoy
  passthrough + observe LB story no longer applies to this fabric.
- **Backups.** `/var/lib/wiremesh` on FI now holds the CA and the whole fabric DB.
  Schedule a periodic encrypted copy off-host; the k8s PVC previously provided this
  implicitly. Do not skip this.
- **Consider a static endpoint override for gateways** (feature gap found 2026-08-01):
  relays can declare `endpoint`, gateways can only be observed. A gateway with a known
  public address (port-forwarded, or on a public host) should be able to declare it and
  skip observation entirely.
- **Consider moving the relay off FI** if it runs there, so controller + relay + a
  production gateway do not share one failure domain.

---

## Rollback (if anything in 4–7 goes wrong)

1. On FI: `systemctl stop wiremesh-controller`.
2. On zolab: `kubectl -n wiremesh scale deploy/wiremesh-controller --replicas=1`.
3. Revert each gateway's `controller-sync`/`observe` to the zolab addresses
   (gw-home: `kubectl patch wiremeshgateways gw-home --type=json -p
   '[{"op":"remove","path":"/spec/observeEndpoint"},{"op":"remove","path":"/spec/syncEndpoint"}]'`).
4. Restart the gateways.

The old PVC still holds the original state, so the fabric returns to exactly its
pre-migration configuration. Nothing in steps 4–7 writes to it.

---

## Field notes — px migration, 2026-08-01

Executed against `px` (`206.83.146.32`) instead of FI. Deviations and findings:

1. **The operator fights a scale-down.** `kubectl scale deploy/wiremesh-controller
   --replicas=0` is immediately reverted by the operator reconciling the
   `WiremeshController` CR. Scale the **operator** to 0 first, then the controller.
   (Runbook step 3 updated accordingly.)

2. **PACKAGING BUG — `wiremesh-controller`'s postinst chowns `/var/lib/wiremesh` to
   `wiremesh:wiremesh`.** On a host that already runs `wiremesh-gateway` (whose identity
   lives in that directory as root-owned files), installing the controller package takes
   the directory away from the gateway and the gateway dies on its next restart with
   `reading identity.json ... Permission denied`. Recovery is
   `chown root:root /var/lib/wiremesh`. The postinst should only touch the directory it
   owns, or the packages should use distinct default data dirs. **Filed as a follow-up.**

3. **Use a separate data dir when co-locating.** `WIREMESH_DATA_DIR=/var/lib/wiremesh-controller`
   keeps control-plane state away from the gateway's identity. The systemd unit's
   `ReadWritePaths=` and `WorkingDirectory=` must be updated to match, or
   `ProtectSystem=strict` blocks the writes.

4. **`fabricctl` is a separate package** — install `wiremesh-fabricctl` on the controller
   host to administer the fabric over the UDS.

5. **Verified exposure after start:** 9400 and 9500 reachable from the internet, 9443
   (admin) correctly refused. px needed no firewall changes.
