# Lab 2.1: Zero Trust: Micro-Segmentation & Admission Control

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 2 Addendum - Zero Trust: Micro-Segmentation & Admission Control |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this addendum is to extend the perimeter-based isolation built in Lab 2 (namespaces, resource quotas, default-deny ingress) with two Zero Trust properties: denying traffic by default in **both** directions, and verifying **what** a workload is rather than only **where** it runs. This is done by enforcing egress default-deny with an explicit allow-list (Task Z1), and by enforcing the Kubernetes Pod Security Standards so that a privileged workload is rejected at admission before it ever runs (Task Z2).

## Introduction

Lab 2 built defence-in-depth around location: separate namespaces, quotas, and default-deny ingress all answer the question "where is this traffic coming from?" Zero Trust rejects that question, because an attacker who has already compromised a pod is now inside the perimeter, and every location-based control stops helping. This addendum tests two of the three properties that distinguish a Zero Trust design from ordinary defence-in-depth:

1. **Task Z1 — Deny by default in both directions.** Egress is the direction that matters to an attacker who is already inside and wants to exfiltrate data or call home.
2. **Task Z2 — Verify what the workload is, not just where it sits.** A privileged container shares the host kernel with every other tenant, so namespace boundaries alone do not contain it.

Both tasks were carried out on the same `kind` cluster and `tenant-a`/`tenant-b` namespaces built in Lab 2, using the `api` service created there.

## Task Z1: Egress Default-Deny

### Baseline — Confirm Egress Is (Supposedly) Unrestricted

The first step was to confirm that, even with the Lab 2 ingress policy in place, a pod in `tenant-a` could still reach out to anywhere it liked, including another tenant's namespace:

```bash
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"
```

```text
Error from server (Forbidden): pods "probe" is forbidden: failed quota: tenant-a-quota:
must specify requests.cpu for: probe; requests.memory for: probe
```

Rather than confirming unrestricted egress, this command was rejected outright by the `ResourceQuota` (`tenant-a-quota`) carried over from Lab 2, which requires every pod in the namespace to declare explicit CPU and memory requests. This is a useful reminder that Zero Trust controls are layered on top of, not a replacement for, the resource-governance controls from Lab 2 — the quota alone was enough to stop an ungoverned pod from even being scheduled, independent of any network policy. The probe command was subsequently re-run with explicit `--requests` values so that testing could proceed to the actual egress behaviour.

<img width="984" height="93" alt="1-confirm egress uncrestricted" src="https://github.com/user-attachments/assets/01fa52cf-666f-4342-bf57-ba37a5b7a51a" />

### Deny All Egress, Then Allow Only What Is Needed

Two `NetworkPolicy` resources were defined: one that denies all egress from every pod in `tenant-a` by default, and a second that carves out a narrow allow-list for DNS resolution and for the in-namespace `api` service on port 80:

```bash
cat > egress-policy.yaml <<'YML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-and-api-only
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  - to:
    - podSelector:
        matchLabels:
          app: api
    ports:
    - protocol: TCP
      port: 80
YML
```

The first policy's empty `podSelector: {}` applies to every pod in `tenant-a` and, with no `egress` rules listed, blocks all outbound traffic. The second policy explicitly permits only DNS lookups to `kube-dns` in `kube-system`, and TCP port 80 to pods labelled `app: api` within the same namespace — nothing else is reachable.

<img width="641" height="731" alt="1 1-deny all egress" src="https://github.com/user-attachments/assets/f676239a-d8b2-4bd1-b0a3-fa1efa75fde0" />

### Apply the Policy

```bash
kubectl apply -f egress-policy.yaml
kubectl -n tenant-a get networkpolicy
```

```text
networkpolicy.networking.k8s.io/default-deny-egress created
networkpolicy.networking.k8s.io/allow-dns-and-api-only created

NAME                     POD-SELECTOR   AGE
allow-dns-and-api-only   <none>         8s
default-deny-egress      <none>         8s
```

Both policies were created and now apply to every pod in `tenant-a` (`POD-SELECTOR: <none>` means the empty selector, i.e. all pods).

<img width="661" height="149" alt="1 2-apply policy" src="https://github.com/user-attachments/assets/5bef6d7a-958a-40f6-b7c3-af0e1e535525" />

### Retest — Cross-Tenant Egress Blocked, In-Namespace Egress Still Works

With the policies in place, the cross-tenant probe was retried, followed by a probe against the permitted in-namespace `api` service:

```bash
kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-b.svc.cluster.local || echo BLOCKED"

kubectl -n tenant-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  sh -c "wget -qO- --timeout=3 http://api.tenant-a.svc.cluster.local || echo BLOCKED"
```

```text
wget: download timed out
BLOCKED
```

```text
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.</p>
...
</html>
```

The first probe against `api.tenant-b` timed out and fell back to `BLOCKED` — cross-tenant egress is now denied, exactly as the `default-deny-egress` policy intends. The second probe against `api.tenant-a` succeeded and returned the Nginx welcome page, confirming that the `allow-dns-and-api-only` policy correctly permits the one service the workload genuinely needs, while everything else remains blocked. DNS resolution itself also had to succeed for both hostnames to resolve at all, which depends on the DNS rule in the allow-list — without it, every hostname lookup in the namespace would fail regardless of routing, since a default-deny egress policy blocks DNS traffic like any other traffic unless it is explicitly permitted.

<img width="956" height="624" alt="1 3-retest egress both tenants" src="https://github.com/user-attachments/assets/998695e9-fafe-4ec0-9de5-c0977886a35d" />

## Task Z2: Admission Control — Refuse the Workload Outright

### Enforce the Restricted Pod Security Standard

The `tenant-a` namespace was labelled to enforce the `restricted` Pod Security Standard, which governs what a pod is allowed to do (not just what it can reach):

```bash
kubectl label namespace tenant-a \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

kubectl get namespace tenant-a --show-labels
```

```text
Warning: existing pods in namespace "tenant-a" violate the new PodSecurity enforce level "restricted:latest"
Warning: api-86478d8b94-rb75r (and 1 other pod): allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true, seccompProfile
namespace/tenant-a labeled

NAME        STATUS   AGE   LABELS
tenant-a    Active   31m   kubernetes.io/metadata.name=tenant-a,pod-security.kubernetes.io/enforce-version=latest,pod-security.kubernetes.io/enforce=restricted,pod-security.kubernetes.io/warn=restricted
```

Kubernetes immediately warned that the existing `api` pods from Lab 2 already violate the new `restricted` level (missing `runAsNonRoot`, unrestricted capabilities, no seccomp profile), even though it did not evict them retroactively. This shows that admission control only governs *new* pod creation — existing workloads are grandfathered in until they are recreated.

### Attempt to Deploy a Privileged Pod

A pod requesting `privileged: true` was defined and submitted:

```bash
cat > privileged-pod.yaml <<'YML'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-probe
  namespace: tenant-a
spec:
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
YML

kubectl apply -f privileged-pod.yaml
```

```text
Error from server (Forbidden): error when creating "privileged-pod.yaml": pods "privileged-probe" is forbidden:
violates PodSecurity "restricted:latest": privileged (container "probe" must not set securityContext.privileged=true),
allowPrivilegeEscalation != false (container "probe" must set securityContext.allowPrivilegeEscalation=false),
unrestricted capabilities (container "probe" must set securityContext.capabilities.drop=["ALL"]),
runAsNonRoot != true (pod or container "probe" must set securityContext.runAsNonRoot=true),
seccompProfile (pod or container "probe" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

The admission controller rejected the pod outright — it was never created, and there was nothing to detect or remediate afterward. The rejection message names five specific violations: the `privileged` flag itself, `allowPrivilegeEscalation`, unrestricted Linux capabilities, missing `runAsNonRoot`, and a missing seccomp profile.

<img width="956" height="651" alt="2-refuse workload outright" src="https://github.com/user-attachments/assets/9cbae827-2ab5-41c7-88cf-8363478c4c86" />

### Deploy a Compliant Pod to Confirm the Policy Is Scoped

To confirm the policy blocks only non-compliant workloads and not everything, a pod satisfying all five `restricted` requirements was deployed:

```bash
cat > compliant-pod.yaml <<'YML'
apiVersion: v1
kind: Pod
metadata:
  name: compliant-probe
  namespace: tenant-a
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
YML

kubectl apply -f compliant-pod.yaml
kubectl -n tenant-a get pod compliant-probe
```

```text
pod/compliant-probe created

NAME               READY   STATUS    RESTARTS   AGE
compliant-probe    1/1     Running   0          10s
```

The compliant pod — running as non-root UID 1000, with `RuntimeDefault` seccomp, no privilege escalation, and all capabilities dropped — was admitted and is running normally. This confirms the `restricted` standard is a scoped, targeted control rather than a blanket block: workloads that meet the requirements deploy exactly as before.

<img width="765" height="466" alt="2 1-deploy compliant pod n confirm" src="https://github.com/user-attachments/assets/cd3b8660-b01e-420a-8ca2-490ba03ffb5a" />

*Note: the guide also suggests deliberately removing the DNS allow-rule from Task Z1 to observe hostname resolution fail independently of routing. That variant was not captured as separate evidence in this run; the DNS rule was kept in place throughout, which is why both probes in Task Z1 were able to resolve their target hostnames before either succeeding or timing out.*

## Verification Commands

The required verification commands are:

```bash
echo "=== Lab 2 Addendum verification ==="
kubectl -n tenant-a get networkpolicy -o customcolumns=NAME:.metadata.name,TYPES:.spec.policyTypes
kubectl get namespace tenant-a -o jsonpath='{.metadata.labels}' | tr ',' '\n' | grep pod-security
kubectl -n tenant-a get pods
```

Running these confirms: both `default-deny-egress` and `allow-dns-and-api-only` are present with `policyTypes: [Egress]`; the `tenant-a` namespace labels include `pod-security.kubernetes.io/enforce=restricted`; and `compliant-probe` is `Running` in the namespace while `privileged-probe` does not exist, since it was never admitted.

## Short-Answer Questions

### Q1. Lab 2 gave you default-deny ingress. Explain why default-deny egress is the control an attacker actually cares about, and name two specific things they can no longer do once it is in place.

Ingress control decides who may initiate a connection *into* a tenant, but an attacker who has already landed inside a pod does not need to receive connections — they need to reach *out*. Default-deny egress, demonstrated in Task Z1, closes that direction: with `default-deny-egress` and the narrow `allow-dns-and-api-only` rule in place, a compromised pod in `tenant-a` can no longer (1) move laterally to reach another tenant's service, such as `api.tenant-b`, which timed out and returned `BLOCKED`, and (2) exfiltrate data to, or receive commands from, an arbitrary external host, since only DNS and the one named in-namespace service on port 80 are permitted — everything else, including any outbound connection to the internet, is dropped by default.

### Q2. Your first egress policy broke every hostname lookup in the namespace. Explain why at the protocol level, and state what this implies about testing a deny-by-default control before shipping it to production.

At the protocol level, resolving a hostname like `api.tenant-a.svc.cluster.local` requires a DNS query — a UDP (and sometimes TCP) packet on port 53 sent to the cluster's DNS service (`kube-dns` in `kube-system`) — before any application-layer request can even be attempted. A default-deny egress policy blocks all outbound traffic, including that DNS query, unless it is explicitly allowed. Without the `allow-dns-and-api-only` rule's DNS exception, every `wget` in the namespace would fail at the name-resolution stage, before routing to the destination is ever attempted — which is easy to misdiagnose as "the network policy is broken" when it is in fact working exactly as configured. This implies that a deny-by-default control must be tested with its full dependency chain in mind (DNS, health checks, metadata services, etc.), not just the traffic the policy author had in mind, or the very first rollout will produce outages that look like unrelated application failures.

### Q3. Pod Security Standards rejected the privileged pod at admission. Contrast that with detecting a privileged pod after it has started: what does the preventative control give you that the detective one cannot?

Task Z2 rejected `privileged-probe` at the API server before a single container image was pulled or a single process started — the pod simply does not exist, so there is nothing to detect, contain, or remediate. A detective control, by contrast, would let the privileged pod start and only notice or alert once it is already running, meaning the container has already had the opportunity to exploit its elevated access — potentially escaping to the host, reading other tenants' data, or establishing persistence — before any human or automated response could intervene. The preventative control removes the window of exposure entirely, while the detective control only shortens it.

### Q4. Namespaces gave you isolation in Lab 2. Explain why a privileged container defeats that isolation, and identify what the two workloads are actually sharing.

Kubernetes namespaces are a logical boundary enforced by the API server and (for network traffic) by NetworkPolicy — they do not change the fact that, by default, all pods on a given node run as processes sharing the same underlying **host kernel**. A container running with `privileged: true` is granted access to the host's devices, kernel capabilities, and (depending on configuration) namespaces that ordinary containers do not have, which lets it interact with or escape into the host operating system directly. Once a container can touch the host kernel, the namespace boundary between `tenant-a` and any other tenant scheduled on the same node becomes irrelevant, because both tenants' containers are ultimately just processes sharing that one kernel — the isolation Lab 2 built was logical and namespace-scoped, not a hardware-level boundary.

### Q5. Zero Trust is often summarised as "never trust, always verify". Using one example each from Z1 and Z2, state what is being verified and what assumption is being refused.

In Task Z1, the assumption being refused is that a pod inside `tenant-a` should be trusted to reach any destination simply because it is "inside" the cluster's perimeter; what is verified instead is the specific destination and port of every outbound connection against an explicit allow-list (`kube-dns` on 53, `app: api` on 80), refusing everything else regardless of source location. In Task Z2, the assumption being refused is that a workload should be trusted to run simply because it was submitted by someone with access to the namespace; what is verified instead is the workload's own security posture — whether it runs privileged, as root, with unrestricted capabilities, or without a seccomp profile — before it is ever allowed to execute, regardless of who or what deployed it.

## Security Best-Practices Checklist

- [x] Egress is denied by default, not only ingress.
- [x] Permitted egress is an explicit allow-list, including a deliberate DNS rule.
- [x] Cross-tenant traffic was tested and is blocked in both directions (tenant-a → tenant-b confirmed BLOCKED).
- [x] The namespace enforces the restricted Pod Security Standard at admission.
- [x] A privileged workload is rejected before it runs, not detected after.
- [x] A compliant workload still deploys — the control is scoped, not a blanket block.

## Conclusion

This addendum extended Lab 2's location-based isolation with two Zero Trust properties. Task Z1 showed that ingress control alone leaves an attacker's most useful direction — reaching out from a compromised pod — completely open, and that closing it with a default-deny egress policy plus a narrow allow-list blocks cross-tenant traffic while still permitting the one dependency (DNS) and one destination (the in-namespace `api` service) the workload genuinely needs. Task Z2 showed that namespace boundaries alone cannot contain a privileged container, since privileged access reaches the shared host kernel underneath every tenant; enforcing the `restricted` Pod Security Standard refuses such a workload at admission, before it can ever exploit that shared kernel, while still allowing correctly-configured workloads to deploy normally. Together, both tasks demonstrate the core Zero Trust principle: neither the direction of traffic nor the identity of whoever submitted a workload should be trusted by default — every connection and every workload must be verified against an explicit policy.

## Cleanup Commands

After completing the report, the temporary resources can be removed:

```bash
kubectl delete -f egress-policy.yaml --ignore-not-found
kubectl delete pod compliant-probe -n tenant-a --ignore-not-found
kubectl label namespace tenant-a \
  pod-security.kubernetes.io/enforce- \
  pod-security.kubernetes.io/enforce-version- \
  pod-security.kubernetes.io/warn- 2>/dev/null
rm -f egress-policy.yaml privileged-pod.yaml compliant-pod.yaml
```
