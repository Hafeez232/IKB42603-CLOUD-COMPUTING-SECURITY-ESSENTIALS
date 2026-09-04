# IKB42603 Lab 4: Access Control and Network Security

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 4 - Access Control and Network Security |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to distinguish and implement authentication (who you are) and authorization (what you may do), and to reduce the attack surface of cloud workloads through network security and host hardening. The lab demonstrates HTTP Basic authentication, a TOTP-based second factor (MFA), Kubernetes RBAC, Docker network segmentation, default-deny firewall rules with iptables, and container hardening combined with vulnerability scanning.

## Introduction

Access control and network security work together to answer two questions: are you who you claim to be, and are you allowed to do this? Session A (Week 7) focuses on identity — authentication and authorization. Session B (Week 8) focuses on containment — restricting what a service or an intruder can reach, and shrinking what could be exploited in the first place. The activities are divided into two sessions:

1. **Session A:** Authentication with HTTP Basic auth, a TOTP second factor, and Kubernetes RBAC.
2. **Session B:** Docker network segmentation, default-deny firewall rules, and container hardening with an image vulnerability scan.

## Session A (Week 7) — Authentication & Authorization

## Task 1: Authentication — a Password-Protected Service

### 1.1 Create the Password File and Serve a Protected Page

A password file was created for user `student` using an Apache htpasswd utility running in a throwaway container, and an Nginx configuration was written to require HTTP Basic authentication for the root location:

```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt

cat > default.conf <<'EOF'
server { listen 80;
 location / { auth_basic "Restricted";
 auth_basic_user_file /etc/nginx/.htpasswd;
 root /usr/share/nginx/html;
 index index.html; } }
EOF
```

The Nginx service was started with the password file and configuration mounted in, publishing port 8080:

```bash
docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd \
  -v $(pwd)/html:/usr/share/nginx/html \
  nginx
```

A request without credentials was rejected:

```bash
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
```

```text
no-creds: 401
```

<img width="724" height="324" alt="1-auth password protected" src="https://github.com/user-attachments/assets/bb9c494b-dc53-4cf4-acda-b90c2f095e25" />

### 1.2 Authenticate Successfully

A request with the correct credentials was sent, and the response headers and body were inspected:

```bash
curl -i -u 'student:P@ssw0rd!' http://localhost:8080/
```

```text
HTTP/1.1 200 OK
Server: nginx/1.31.3
Content-Type: text/html

<h1>Authenticated successfully!</h1>
```

This shows that the server rejected the anonymous request (401) and accepted the request only once the correct username and password were supplied (200), demonstrating that authentication controls who is let in before any resource is served.

<img width="707" height="218" alt="1 1-verification" src="https://github.com/user-attachments/assets/6a797a25-a57f-4e9e-96ad-c75e6f8d6369" />

## Task 2: Add a Second Factor (MFA / TOTP)

A random shared secret was generated and encoded in base32, and the current TOTP code was produced from it, simulating what an authenticator app would display:

```bash
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol this secret in an authenticator app: $SECRET"
oathtool --totp -b "$SECRET"
```

```text
Enrol this secret in an authenticator app: 4TRLJBSUGEK5MF2WC5KTQABZTVGJXUUZ
914462
```

A code entered by the user was then compared against a freshly computed TOTP value for the same secret:

```bash
read -p 'Enter the 6-digit code: ' CODE
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

```text
Enter the 6-digit code: 942843
MFA OK
```

The code entered matched the value recomputed from the shared secret at verification time, so the check returned `MFA OK`. MFA adds a second, independent factor (something you have, the TOTP generator) on top of the password (something you know), so a stolen password alone is no longer enough to authenticate.

<img width="810" height="180" alt="2-second factor MFA" src="https://github.com/user-attachments/assets/22b78d05-97c0-4506-9afc-3af483f31b2c" />

## Task 3: Authorization — RBAC Roles

A local Kubernetes cluster was created, and a namespace, a service account, a role limited to reading pods, and a role binding were configured:

```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
```

The permissions granted to the `dev` service account were then checked against three different actions:

```bash
SA=system:serviceaccount:app:dev
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

```text
yes
no
no
```

The service account was authorized to list pods, since `dev-role` explicitly grants `get,list` on `pods`, but it was denied both creating deployments and deleting pods, since those verbs and/or resources were never granted. This demonstrates the difference between authentication (Task 1, proving identity) and authorization (Task 3, deciding what an authenticated identity may do) — RBAC enforces least privilege even for an identity that has already been verified.

<img width="717" height="581" alt="3-" src="https://github.com/user-attachments/assets/fbd3798e-9930-4687-94bb-5d32299688cc" />

*End of Session A. The 401/200 results, the MFA OK output, and the three `can-i` results were kept as evidence, and the auth service was stopped with `docker stop authsvc`.*

## Session B (Week 8) — Network Security & Hardening

## Task 4: Network Segmentation (Three-Tier)

Two isolated Docker networks were created, and the database, application, and web tiers were attached so that only the tiers that need to communicate share a network:

```bash
docker network create frontend-net
docker network create backend-net

docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx
```

`db` was placed only on `backend-net`, `app` was connected to both networks so it can bridge the tiers, and `web` was placed only on `frontend-net`, so `web` and `db` share no common network.

<img width="722" height="435" alt="4-network segmentation" src="https://github.com/user-attachments/assets/f9b0315f-e2e7-49cc-b30a-c0aec37d5854" />

### 4.1 Verify Segmentation

The web tier attempted to reach the database directly, and the application tier attempted to reach the database over the shared backend network:

```bash
docker exec web sh -c 'apt-get update -qq && apt-get install -y -qq netcat-openbsd > /dev/null && nc -z -w3 db 6379 && echo REACHABLE || echo BLOCKED'
docker exec app sh -c 'apt-get update -qq && apt-get install -y -qq netcat-openbsd > /dev/null && nc -z -w3 db 6379 && echo REACHABLE'
```

```text
nc: getaddrinfo for host "ddb" port 6379: Temporary failure in name resolution
BLOCKED
Connection to db (172.20.0.2) 6379 port [tcp/*] succeeded!
REACHABLE
```

The `web` container could not resolve or reach `db` at all, since it is on a different Docker network (`frontend-net`) and has no name resolution or route to the backend tier — the connection attempt returned `BLOCKED`. The `app` container, which is attached to `backend-net` alongside `db`, resolved the hostname to `172.20.0.2` and successfully connected, returning `REACHABLE`. This confirms that the database is unreachable from the internet-facing web tier: even if the web tier were compromised, network segmentation prevents an attacker from talking directly to the data.

<img width="769" height="671" alt="4 1-verification" src="https://github.com/user-attachments/assets/c5bb6566-756a-42e7-8868-50329e30d22a" />

## Task 5: Firewall Rules (Default-Deny)

A throwaway container with `NET_ADMIN` capability was used to model a host-level default-deny firewall, allowing only HTTPS (443) and loopback traffic:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
  apk add -q iptables; \
  iptables -P INPUT DROP; \
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
  iptables -A INPUT -i lo -j ACCEPT; \
  iptables -L INPUT -n'
```

```text
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
```

The default `INPUT` policy is `DROP`, meaning every packet is rejected unless a rule explicitly allows it. Only TCP port 443 and loopback traffic were explicitly accepted. This mirrors how cloud security groups work: nothing is permitted unless it is deliberately opened, which is the least-privilege model applied to the network layer.

<img width="700" height="183" alt="5-Firewall rules" src="https://github.com/user-attachments/assets/e2e35092-bf6e-4698-a104-b780766f5daa" />

## Task 6: Container / Host Hardening

### 6.1 Run a Hardened Container

A container was started with a non-root user, a read-only root filesystem, all Linux capabilities dropped, privilege escalation disabled, and a writable `tmpfs` mount only where needed:

```bash
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
```

```text
User=1000:1000 ReadOnly=true
```

The inspect output confirms the container runs as non-root UID 1000 with a read-only root filesystem. Combined with `--cap-drop=ALL` and `no-new-privileges`, this removes the capabilities that most container-breakout and privilege-escalation techniques rely on, and prevents the container process from writing to its own filesystem even if it is compromised.

<img width="768" height="489" alt="6-Hardened run" src="https://github.com/user-attachments/assets/26e335c0-e5cc-438c-9761-08c5c3169607" />

### 6.2 Scan an Image for Known Vulnerabilities

Trivy was used to scan an Nginx image for HIGH and CRITICAL vulnerabilities:

```bash
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

```text
Report Summary
Target          Type     Vulnerabilities  Secrets
nginx:alpine    alpine   4                -

nginx:alpine (alpine 3.24.1)
=============================
Total: 4 (HIGH: 4, CRITICAL: 0)
```

The scan reported four HIGH-severity vulnerabilities and no CRITICAL vulnerabilities in the `nginx:alpine` base image. Scanning before deployment identifies known CVEs in OS packages and libraries so they can be patched or the base image updated before the container is exposed to production traffic.

<img width="1315" height="381" alt="6 1-scan image for known vuln" src="https://github.com/user-attachments/assets/4c49c3dd-5a55-457d-8e99-dd347030ebc4" />

*In the report, three hardening measures applied and the attack each blunts: running as non-root (blunts privilege escalation to root), a read-only root filesystem (blunts persistence and tampering by malware), and dropping all capabilities with `no-new-privileges` (blunts most kernel-level container-breakout techniques).*

## Verification Commands

The required verification commands are:

```bash
kubectl get rolebinding dev-rb -n app -o yaml
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

The role binding output confirms `dev-rb` binds the `dev-role` (Role, `get`/`list` on `pods`) to the `dev` service account in namespace `app`, matching the `yes`/`no`/`no` results from Task 3. The capability-drop output confirms `["ALL"]`, matching the hardened container evidence from Task 6.

## Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Task 1 is authentication: the Nginx service checked whether the caller could prove their identity with a username and password, rejecting anonymous requests with 401 and accepting only the request with correct credentials. Task 3 is authorization: once the `dev` service account's identity was established, RBAC decided what that identity was permitted to do, allowing it to list pods but denying it permission to create deployments or delete pods. Authentication answers "who are you?", while authorization answers "what are you allowed to do now that we know who you are?" — an entity can be authenticated and still be denied an action.

### Q2. Why is MFA so effective, and which attacks does it defeat?

MFA requires two factors from different classes — something you know (a password) and something you have (a TOTP generator/authenticator app) — so a compromised password alone is not enough to authenticate. It defeats the majority of credential-based attacks: phishing that only captures a password, credential stuffing using passwords leaked from other breaches, brute-force guessing, and keylogging of a password, because the attacker would also need the time-synchronized secret used to generate valid codes.

### Q3. How does network segmentation limit the damage of a compromised web server?

By placing the database only on `backend-net` and the public-facing web tier only on `frontend-net`, the two tiers share no network path. Task 4 showed that `web` could not resolve or reach `db` at all, while `app`, which bridges both networks, could. If an attacker compromises the web server, segmentation means they still cannot talk directly to the database — they would need to also compromise the application tier that legitimately bridges the two networks, containing lateral movement instead of allowing a single breach to expose the data tier.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy (`iptables -P INPUT DROP`) rejects every incoming packet unless a specific rule explicitly allows it, so only intentionally opened ports — in Task 5, TCP 443 and loopback — are reachable. This is the same least-privilege model used by cloud security groups: nothing is allowed unless the owner deliberately opens it, which minimizes the exposed attack surface compared with an allow-by-default posture that must anticipate every service to block.

### Q5. List the hardening measures you applied and the attack surface each one removes.

- **Non-root user (`--user 1000:1000`)** — removes the ability for a compromised process to act with root privileges inside the container, blunting privilege-escalation attacks.
- **Read-only root filesystem (`--read-only`, with `--tmpfs /tmp` for the one directory that needs to be writable)** — prevents an attacker from writing malware, modifying binaries, or persisting changes inside the container.
- **Dropped Linux capabilities and no new privileges (`--cap-drop=ALL`, `--security-opt no-new-privileges`)** — removes the kernel capabilities that many container-breakout and privilege-escalation exploits depend on, and blocks setuid-based privilege escalation.
- **Image vulnerability scanning (Trivy)** — identifies known CVEs in OS packages before deployment, closing off exploitation of already-patched vulnerabilities.

## Security Best-Practices Checklist

- [x] Service requires authentication (unauthenticated requests rejected with 401).
- [x] MFA / second factor implemented and validated (`MFA OK`).
- [x] Authorization enforced by RBAC (least privilege; unauthorized actions denied).
- [x] Network segmented so the data tier is unreachable from the front tier (`web` → `db` BLOCKED).
- [x] Default-deny firewall with explicit allow rules (INPUT policy DROP, port 443 and loopback ACCEPT).
- [x] Container hardened: non-root, minimal, capabilities dropped, read-only; image scanned.

## Conclusion

This lab demonstrated a complete set of access-control and network-security controls across two sessions. Session A showed that authentication (HTTP Basic auth and TOTP-based MFA) verifies identity before any resource is served, while Kubernetes RBAC enforces authorization by deciding what a verified identity may actually do. Session B showed that network segmentation contains lateral movement by keeping the database tier unreachable from the web tier, a default-deny firewall policy minimizes the ports exposed to the network, and container hardening — non-root execution, a read-only filesystem, dropped capabilities, and vulnerability scanning — reduces what an attacker could exploit even after gaining a foothold. Together, these exercises show that identity, network boundaries, and host hardening must all be enforced for a defense-in-depth cloud security posture.

## Cleanup Commands

After completing the report, the temporary resources can be removed:

```bash
docker rm -f authsvc db app web hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
kind delete cluster --name ccse-lab4
```
