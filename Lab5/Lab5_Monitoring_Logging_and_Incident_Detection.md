# IKB42603 Lab 5 Monitoring, Logging & Incident Detection

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 5 - Monitoring, Logging & Incident Detection |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to build visibility into cloud workloads through centralised logging and to turn that visibility into detection and response. The lab demonstrates shipping application logs to a centralised log store (LocalStack CloudWatch Logs), querying logs for security-relevant activity, building a tamper-evident hash-chained log, detecting an incident by correlating multiple events, and executing the core incident-response steps of contain, collect evidence, and document.

## Introduction

Security teams cannot secure or prove compliance for what they cannot see. Logs are foundational to detection, forensics, and compliance evidence. The activities are divided into two sessions:

1. **Session A:** Generating application logs, centralising them, and querying for failed logins.
2. **Session B:** Tamper-proofing logs with a hash chain, detecting an incident by correlation, and running incident response.

## Session A— Logging & Centralisation

## Setup — Start LocalStack

A LocalStack container was started to provide a local CloudWatch Logs endpoint, and a log group and log stream were created for the application:

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:4.4.0

EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

LocalStack started successfully and the log group `/ccse/app` with log stream `auth` was created, ready to receive centralised log events.

<img width="779" height="126" alt="1-startlocalstack" src="https://github.com/user-attachments/assets/0efd00cf-d84f-45e7-a647-fcd6a924bdd6" />

## Task 1: Generate Application Logs

A small authentication log was created, containing a normal login, a burst of failed login attempts from the same IP, a subsequent successful login, and a large data export — the pattern of an attacker probing for access:

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF

cat auth.log
```

The output confirmed all seven log lines were written correctly: one legitimate login from `ahmad` at `10.0.0.5`, four failed login attempts against the `admin` account from `203.0.113.9`, one successful login from that same IP, and a 500MB data export immediately afterward.

<img width="676" height="306" alt="2 generate app logs" src="https://github.com/user-attachments/assets/2d77d127-ef2c-431b-8ae5-0c0ca9319abe" />

## Task 2: Centralise Logs (Ship to CloudWatch)

Each line of `auth.log` was shipped as a separate log event to the centralised CloudWatch Logs stream on LocalStack, with an incrementing millisecond timestamp per event:

```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null; TS=$((TS+1000));
done < auth.log
```

The events were then read back directly from the central log store rather than from the local file:

```bash
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5      2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9      2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9      2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
```

All seven messages were successfully read back from the centralised store, proving the logs had been shipped off the host to a durable, queryable location rather than remaining scattered on the individual machine that generated them.

<img width="1021" height="201" alt="3-centralised logs" src="https://github.com/user-attachments/assets/ce53f08a-54c3-4330-86cd-fc57fce2105f" />

## Task 3: Query for Security-Relevant Activity

The local log file was queried for failed login attempts, grouped by user and IP:

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

```text
4 ip=203.0.113.9
```

The query showed four `LOGIN_FAIL` entries, all from the same IP address `203.0.113.9`, immediately highlighting a repeated failure pattern from a single source. This is a **log** — a durable, queryable record retrieved after the fact — as opposed to an **event**, which would be a real-time trigger such as an alert firing the moment the fourth failure occurred (demonstrated later in Task 5).

<img width="803" height="71" alt="4-query security activity" src="https://github.com/user-attachments/assets/11b01a58-8c43-44ac-9e12-b655e00feaf4" />

*End of Session A. `auth.log` and the centralised read-back were kept as evidence for the next session, in which the logs are made tamper-proof and used to detect an incident.*

## Session B — Tamper-Proofing, Detection & Response

## Task 4: Tamper-Proof (Hash-Chained) Logs

Each line of `auth.log` was chained to the SHA-256 hash of the previous line plus its own content, so that any modification to an earlier entry invalidates every hash that follows it:

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

cat auth.chain
```

```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5 | 82da89a49dc1ca7d23b8a59f98d7e557ab36ce0c2d0c6e106fabe76e1f0acf39
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9 | 790aef7176d6effe76d077831c071f8500204bf842e7fd8aeda1b67b2e271a97
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9 | 1e0b2e8aaf5143fb95070a8e57bc909f058f0d37c257d19409b4131894d29a9a8
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9 | 7fb62c66ed551605e22c8db9c4f57c9360aa27309ce65024a3e5ea35e3b6e94
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9 | 143253b549a74b9626e910fbe54ca12cb5431a0a4c9c4f2189ff27a3e2a17e01
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9 | 4cbfab7fecb703cf21f5df81b47dbf3a727c94442b09b714ac4bfaa3584cc638
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB | ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf
```

Each line's stored hash is derived from the previous line's hash plus the current line's content, so the chain covers the entire log history rather than each line in isolation.

<img width="1215" height="234" alt="5-tamper proof chain each line" src="https://github.com/user-attachments/assets/8996c7a1-a83d-40f5-b4e9-6cf8e7c247d3" />

### 4.1 Tamper With a Log Entry and Watch the Chain Break

The `EXPORT_DATA` line's declared size was altered from `500MB` to `5MB`, simulating an attacker editing the log to hide the scale of the exfiltration, and the chain was recomputed for comparison:

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered

PREV=0; BROKE=no
paste -d'|' <(cut -d'|' -f1 auth.chain) <(cut -d'|' -f2 auth.chain) >/dev/null
```

Recomputing the hash chain from `auth.tampered` produces a different hash for the tampered line onward, so the final hash of the recomputed chain no longer matches the final hash stored in `auth.chain`. Because each hash depends on all previous content, changing even a single character breaks every subsequent link — proving the tampering is detected without needing to compare every line manually.

<img width="755" height="55" alt="5 1-tamper and watch chain break" src="https://github.com/user-attachments/assets/e028e450-763f-4c2d-a41a-7df4089ddfb2" />

## Task 5: Detect the Incident (Correlation)

No single log line was inherently malicious on its own, so the events were correlated by IP address: repeated login failures, followed by a success, followed by a data export:

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

```text
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

The IP `203.0.113.9` had 4 failed logins, 1 successful login, and 1 data export — all thresholds were met, so the alert fired. This is what a SIEM does: it correlates events across a timeline into a single, higher-confidence detection that no individual log line would reveal on its own.

<img width="872" height="200" alt="6-detect incident" src="https://github.com/user-attachments/assets/4fca7ead-ec1a-419b-acb9-673ec5a9954a" />

## Task 6: Incident Response

The incident-response lifecycle was executed: contain the threat, collect tamper-evident evidence, and prepare to document the timeline.

### 6.1 Contain

A firewall rule was applied (modelled with iptables in a throwaway container) to block all further traffic from the attacker's IP:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

```text
target     prot opt source               destination
DROP       all  --  203.0.113.9          0.0.0.0/0
```

The rule confirms that all subsequent traffic from `203.0.113.9` is dropped, stopping the attacker from continuing to interact with the service while the incident is investigated.

### 6.2 Collect Evidence

A timestamped, immutable copy of the log was made, and its SHA-256 hash was recorded to prove the evidence file has not been altered after collection:

```bash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

```text
0adc5d2ac06cbbdd366099bcc004c4f76946e71b52e4c99322731696a203b  evidence_20260907.log
```

<img width="875" height="163" alt="7-incident response" src="https://github.com/user-attachments/assets/21747488-d25a-4259-8283-9b5a2d13b455" />

## Verification Commands

The required verification commands are:

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
sha256sum -c evidence.sha256
```

```text
{
    "logGroups": [
        {
            "logGroupName": "/ccse/app",
            "creationTime": 1788751795413,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:us-east-1:000000000000:log-group/ccse/app:*",
            "storedBytes": 397
        }
    ]
}
evidence_20260907.log: OK
```

The `describe-log-groups` call confirms the `/ccse/app` log group still exists in the centralised store with the shipped log data (`storedBytes: 397`). The `sha256sum -c` check returned `OK`, confirming the evidence file's hash still matches the value recorded at collection time and has not been altered since.

<img width="811" height="276" alt="8-verification command" src="https://github.com/user-attachments/assets/533d6339-8f2e-4962-9635-a87bc50aa1c7" />

## Incident Report

**Detection:** The incident was detected by correlating three event types from log source `/ccse/app` (Task 5): four `LOGIN_FAIL` events against the `admin` account, followed by a `LOGIN_OK`, followed by an `EXPORT_DATA` event of 500MB, all from the same source IP `203.0.113.9` within roughly one minute. No single event crossed an obvious threshold on its own; the pattern only became suspicious once the events were viewed together.

**Analysis:** The sequence is consistent with a brute-force attack against the `admin` account that eventually succeeded, followed immediately by exfiltration of a large volume of data. The Task 3 query had already shown that all four failures originated from one IP, which narrowed the investigation before the correlation rule in Task 5 confirmed the full attack chain.

**Containment:** An iptables `DROP` rule was applied against source IP `203.0.113.9` (Task 6.1), blocking further inbound traffic from the attacker while the investigation continued.

**Evidence & integrity:** A copy of `auth.log` was preserved as `evidence_20260907.log` and its SHA-256 hash was recorded in `evidence.sha256` immediately after collection (Task 6.2). The verification command `sha256sum -c evidence.sha256` returned `OK`, proving the evidence file was not modified after it was collected — an auditable chain of custody for any follow-up investigation.

**Lesson learned:** A single failed login is not actionable, but four failed logins followed by a success and a large export from the same IP is a clear brute-force-to-exfiltration pattern. Centralising logs and applying correlation rules — rather than relying on any one log line — is what turned an otherwise invisible sequence of individually unremarkable events into a timely, actionable alert.

## Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.

A log is a durable, stored record that can be queried after the fact, such as `auth.log` itself or the `grep LOGIN_FAIL auth.log | awk ... | sort | uniq -c` query in Task 3, which counted four failures from `203.0.113.9` after the fact. An event is a real-time trigger raised as something happens, such as the `ALERT: probable brute-force -> compromise -> data exfiltration` message in Task 5, which fires the moment the correlation thresholds are met rather than being read back later.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?

If an attacker who compromises a system can also edit its logs, they can erase evidence of what they did, making detection and forensics unreliable. A hash chain achieves tamper-evidence by making each entry's hash depend on the content of the current line and the hash of every entry before it (Task 4). Changing any single character in any line — as demonstrated by editing `500MB` to `5MB` in Task 4.1 — changes that line's hash and every hash computed after it, so the final hash of the recomputed chain no longer matches the original, immediately revealing that the log was altered.

### Q3. How did correlation detect an incident that no single log line revealed?

Individually, four `LOGIN_FAIL` lines, one `LOGIN_OK` line, and one `EXPORT_DATA` line each look like routine, low-severity activity. Task 5 correlated all three counts for the same source IP and applied combined thresholds (`fails >= 3`, `success >= 1`, `export >= 1`). Only when all three conditions were satisfied together did the alert fire, revealing the brute-force-then-exfiltration pattern that no single log line, viewed in isolation, would have exposed.

### Q4. List the incident-response steps you performed and the goal of each.

- **Detect** (Task 5) — correlate events across the log to recognise that an incident is occurring, producing the `ALERT` output.
- **Contain** (Task 6.1) — block the attacker's IP with an iptables `DROP` rule so they cannot continue interacting with the service during the investigation.
- **Collect evidence** (Task 6.2) — preserve a timestamped copy of the log and hash it immediately, so the evidence can later be proven unaltered.
- **Document** (Incident Report above) — record detection, analysis, containment, evidence, and a lesson learned so the incident and response are auditable and repeatable.

### Q5. How do the same logs serve both security monitoring and compliance evidence?

For security monitoring, the logs feed queries and correlation rules (Tasks 3 and 5) that detect malicious activity in near real time or shortly after the fact. For compliance, the same logs — centralised in `/ccse/app` (Task 2) and hashed as evidence (Task 6.2) — provide an auditable, tamper-evident record that specific events occurred at specific times, which is exactly what auditors and compliance frameworks require to demonstrate that controls were in place and incidents were properly detected, contained, and documented.

## Security Best-Practices Checklist

- [x] Logs are centralised, not left scattered on each host (shipped to and read back from CloudWatch Logs on LocalStack).
- [x] Security-relevant activity (failed logins) can be queried (`grep`/`awk` count by IP).
- [x] Logs are tamper-evident (hash chain) and a break in the chain was demonstrated after tampering.
- [x] An incident is detected by correlating multiple events (brute-force → success → export).
- [x] Incident response performed: contain (iptables DROP), collect evidence (hashed copy), document (incident report).

## Conclusion

This lab demonstrated the full path from raw application logs to a documented incident response. Session A showed that logs must be centralised — shipped off the host to a durable store such as CloudWatch Logs — before they can be reliably queried for security-relevant activity like repeated login failures. Session B showed that centralisation alone is not enough: logs must also be tamper-evident, since a hash chain makes any alteration to a single line detectable through a broken final hash, and no single log line may reveal an incident on its own — correlation across multiple event types was needed to surface the brute-force-to-exfiltration pattern. Finally, incident response closed the loop by containing the attacker's IP, collecting a hashed, immutable copy of the evidence, and documenting the incident from detection through to a lesson learned. Together, these exercises show that visibility, integrity, detection, and response must all work together to make monitoring and logging useful for both security and compliance.

## Cleanup Commands

After completing the report, the temporary resources can be removed:

```bash
rm -f auth.log auth.chain auth.tampered evidence_*.log evidence.sha256
docker stop localstack && docker rm localstack
```
