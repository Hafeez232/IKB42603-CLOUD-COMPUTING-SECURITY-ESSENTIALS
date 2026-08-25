# Lab 2: Secure Isolation and Multi-Tenancy

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 2 - Secure Isolation and Multi-Tenancy |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to understand and implement secure isolation in a shared cloud environment. Kubernetes namespaces are used to separate tenants on the same cluster, resource quotas are applied to control shared capacity, and Calico is installed so that Kubernetes NetworkPolicies are enforced. The lab also demonstrates per-tenant secret isolation using RBAC and explains data remanence, normal deletion, and secure wiping of sensitive files.

## Introduction

Multi-tenancy allows multiple customers or workloads to share infrastructure. Although sharing improves resource efficiency, it creates security risks if compute, network, storage, and resource-consumption boundaries are not configured correctly. This lab uses a local kind cluster with Calico and two namespaces, `tenant-a` and `tenant-b`, to demonstrate both the default-open condition and the security controls used to reduce cross-tenant access.

## Step 1: Create a Kubernetes Cluster with the Default CNI Disabled

The default kind CNI was disabled so that a policy-enforcing CNI could be installed separately. The cluster was created with the name `ccse-lab2` and pod subnet `192.168.0.0/16`:

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

The cluster creation output confirmed that the node image was prepared, the control plane started, and the Kubernetes configuration was written. Disabling the default CNI makes it possible to use Calico for network-policy enforcement.

<img width="753" height="321" alt="1-create cluster cni disabled" src="https://github.com/user-attachments/assets/45bcd46e-aae7-4727-9e95-f396c0b72888" />

## Step 2: Install Calico

Calico was installed from the Kubernetes manifest supplied in the lab guide:

```bash
kubectl apply -f \
  https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

The output showed that Calico controllers, service accounts, configuration, and custom resource definitions were created.

<img width="759" height="199" alt="1 1-install calico" src="https://github.com/user-attachments/assets/c4a28989-fcf3-4f7f-8722-968a91367f8c" />

The Calico node daemonset was then checked until it completed successfully:

```bash
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

The result `daemon set "calico-node" successfully rolled out` confirmed that the policy-enforcing CNI was ready.

<img width="858" height="75" alt="1 2-rolled out calico" src="https://github.com/user-attachments/assets/90c6c9f7-94ec-470e-b39e-dc75c0f91f72" />

## Step 3: Create Two Tenant Namespaces and Web Services

Two namespaces were created to represent separate customers sharing one Kubernetes cluster:

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```

A web deployment and service were created in each namespace:

```bash
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

The pods were running and each tenant had a ClusterIP service named `web`. This demonstrates compute isolation by namespace while the workloads still share the same physical or virtual cluster infrastructure.

<img width="783" height="429" alt="2-create and deploy two namespace and web server" src="https://github.com/user-attachments/assets/08a88dc3-a313-4b84-80f7-f0d6e7e910b1" />

## Step 4: Observe the Default-Open Network Risk

The ClusterIP of tenant B's service was retrieved:

```bash
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

The service IP shown was `10.96.164.172`. A temporary curl pod in tenant A then attempted to contact tenant B:

```bash
kubectl -n tenant-a run probe --rm -it \
  --image=curlimages/curl --restart=Never -- \
  curl -s -m 5 http://10.96.164.172 -o /dev/null \
  -w 'HTTP %{http_code}\n'
```

The result was `HTTP 200`. This proves that, before a NetworkPolicy is applied, a pod in one namespace can reach a service in another namespace. Namespace separation alone does not automatically provide network isolation.

<img width="857" height="110" alt="3-observe tenant b service" src="https://github.com/user-attachments/assets/9e23f786-30b0-4e5e-bdaf-955499ef4468" />

This default-open behaviour is dangerous in a multi-tenant cloud because a compromised workload could scan or attack services belonging to other tenants.

## Step 5: Apply a Resource Quota

A ResourceQuota was created for tenant A to limit its use of shared capacity:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF
```

The quota was inspected with:

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

The quota limits tenant A to five pods, one CPU of requested capacity, and 512 MiB of requested memory. This helps prevent a noisy neighbour from consuming all shared cluster resources.

<img width="847" height="310" alt="4-apply resource quotas" src="https://github.com/user-attachments/assets/902792d7-b786-4c12-bf3f-32cf4fbbb578" />

## Step 6: Apply Default-Deny Network Isolation

A default-deny ingress policy was applied to all pods in tenant B:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

The policy selects every pod in tenant B and denies all incoming traffic unless another policy explicitly allows it. This follows the security principle of **deny by default and permit by exception**.

<img width="943" height="308" alt="5-deny network isolation" src="https://github.com/user-attachments/assets/3281dfc6-7c0f-4655-979f-052e5ba33d2a" />

### Post-Policy Verification Note

The guide instructs the same cross-tenant probe to be run again and expects it to time out after the NetworkPolicy is active. In the supplied screenshot, the probe was rejected by the ResourceQuota because the temporary pod did not specify CPU and memory requests:

```text
Error from server (Forbidden): pods "probe" is forbidden:
failed quota: tenant-a-quota: must specify requests.cpu for: probe,
requests.memory for: probe
```

Therefore, this screenshot documents a quota-admission failure, not a network timeout. The initial `HTTP 200` is valid evidence of the default-open state. To obtain the guide's intended post-policy network result, the probe should be run with resource requests or after adjusting the quota, while keeping the NetworkPolicy applied.

## Step 7: Create Per-Tenant Secrets

Each tenant received a separate secret with a different value:

```bash
kubectl -n tenant-a create secret generic data \
  --from-literal=value=SECRET_A

kubectl -n tenant-b create secret generic data \
  --from-literal=value=SECRET_B
```

The screenshot confirms that both secrets were created in their respective namespaces. Namespace separation prevents the secrets from being treated as one shared object.

<img width="912" height="94" alt="6-create secret" src="https://github.com/user-attachments/assets/f4a34107-f7fc-42ad-a76a-4134a6878384" />

## Step 8: Apply RBAC for Secret Isolation

A service account representing tenant A's application was created:

```bash
kubectl -n tenant-a create serviceaccount app-a
```

A Role allowing only `get` on secrets was created in tenant A, and the Role was bound to the service account:

```bash
kubectl -n tenant-a create role reader \
  --verb=get --resource=secrets

kubectl -n tenant-a create rolebinding rb \
  --role=reader \
  --serviceaccount=tenant-a:app-a
```

This gives `app-a` permission to read secrets in tenant A only. It does not grant access to tenant B.

<img width="770" height="113" alt="7 1-show service" src="https://github.com/user-attachments/assets/c1420b11-c621-462d-8081-93246d6611cf" />

The service account's permissions were tested as follows:

```bash
SA=system:serviceaccount:tenant-a:app-a

kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

The results were:

| Request | Result | Explanation |
|---|---|---|
| Read secrets in tenant A | `yes` | The Role grants `get` on secrets in tenant A. |
| Read secrets in tenant B | `no` | The Role and RoleBinding are scoped to tenant A. |

<img width="940" height="152" alt="7-apply service to tenant a" src="https://github.com/user-attachments/assets/c266344a-03e5-4dfb-b24f-41b0a0574fe8" />

This demonstrates storage isolation enforced by Kubernetes authorization. The application can access its own tenant's secret but cannot read another tenant's secret.

## Step 9: Demonstrate Data Remanence

Data remanence is the possibility that data remains recoverable after a normal delete operation. A sensitive file was created in a Docker volume, synchronized, deleted, and scanned:

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; \
   rm /data/phi.txt; grep -a SENSITIVE /data/* 2>/dev/null; \
   echo scan-done'
```

The command completed with `scan-done`. A normal filesystem delete removes the directory entry, but on some storage systems the underlying bytes may remain until overwritten.

<img width="851" height="198" alt="8-create file n delete" src="https://github.com/user-attachments/assets/08b31f4b-ca2a-4e25-ab6b-c15f7d6301f8" />

## Step 10: Securely Wipe the Data

For the demonstration, the file was overwritten with zero bytes before it was deleted:

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; \
   rm /data/phi2.txt; echo wiped'
```

The output showed that 1024 bytes were written and ended with `wiped`. Overwriting before deletion reduces the chance of recovering the original contents in this local volume demonstration.

In cloud storage, customers generally cannot control the provider's physical blocks. The preferred solution for reliable cloud data erasure is **cryptographic erasure**: encrypt the data and destroy the encryption key so that remaining ciphertext is unusable.

<img width="890" height="127" alt="9-secure wipe" src="https://github.com/user-attachments/assets/0d72066f-eb86-4f19-80bc-1d82f4782a92" />

## Verification Commands

The guide specifies these commands to verify the network policy and quota:

```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

The supplied evidence confirms the `tenant-a-quota` resource and the `default-deny-ingress` policy applied to tenant B.

## Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default?

Namespaces organize Kubernetes resources but do not automatically block pod-to-pod network traffic. Unless a NetworkPolicy is enforced, the cluster network normally permits communication between namespaces. This is dangerous in a multi-tenant cloud because a compromised tenant workload may discover and attack another tenant's services.

### Q2. Explain the default-deny principle.

Default-deny means that traffic or access is blocked unless an explicit rule permits it. The `default-deny-ingress` NetworkPolicy selects all pods in tenant B and denies ingress. Additional allow policies can then be added for approved traffic, such as same-namespace application communication.

### Q3. How do virtual machines and containers differ in isolation strength?

Containers share the host kernel, so a kernel vulnerability or container escape could affect other workloads. Virtual machines include separate guest operating systems and kernels, providing a stronger boundary. A VM boundary is appropriate for highly sensitive tenants, untrusted workloads, regulatory requirements, or workloads needing stronger isolation than a shared container kernel provides.

### Q4. What is data remanence, and why is cryptographic erasure preferred in the cloud?

Data remanence is the persistence of data after a file is logically deleted. Cloud customers usually cannot access or overwrite the provider's physical storage blocks directly. Cryptographic erasure is preferred because destroying the encryption key makes the remaining data unreadable even if storage blocks or backups still exist.

### Q5. Which isolation dimensions did the tasks exercise?

| Isolation dimension | Lab activities |
|---|---|
| Compute isolation | Separate tenant namespaces, deployments, and ResourceQuota. |
| Network isolation | Initial cross-tenant HTTP test and the default-deny NetworkPolicy. |
| Storage and secret isolation | Per-tenant secrets and namespace-scoped RBAC. |
| Data lifecycle protection | Normal deletion, remanence scan, and overwrite-before-delete. |

## Security Best-Practices Checklist

- [x] Tenants were separated into distinct namespaces.
- [x] Calico was installed to support NetworkPolicy enforcement.
- [x] A default-deny ingress policy was applied to tenant B.
- [x] A ResourceQuota limited tenant A's shared resource consumption.
- [x] Per-tenant secrets were created.
- [x] RBAC allowed tenant A's service account to read only tenant A secrets.
- [x] Secure deletion and data remanence were demonstrated.
- [x] Cryptographic erasure was identified as the practical cloud solution.

## Conclusion

This lab demonstrated that namespace separation alone is not enough for secure multi-tenancy. Before network controls were applied, tenant A successfully reached tenant B's web service with `HTTP 200`. ResourceQuota provided compute-capacity protection, while Calico and a default-deny NetworkPolicy supplied a network-isolation boundary. Kubernetes RBAC further restricted tenant A's service account to its own secrets, producing `yes` for tenant A and `no` for tenant B. Finally, the data-remanence exercise showed why sensitive data requires secure deletion and, in cloud storage, cryptographic erasure.

## Cleanup

After completing the report, the lab resources can be removed with:

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```
