# Lab 5.1: Management Plane Audit, Backup and BCDR

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 5.1 – Management Plane and Business Continuity, Disaster Recovery |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to reconstruct a management-plane audit trail, protect that trail in a separate trust boundary, and test backup and disaster recovery procedures using LocalStack. The lab demonstrates how administrative cloud changes differ from application activity, how log integrity can be validated with a digest, why a separate backup is stronger than bucket versioning alone, and how to measure Recovery Time Objective (RTO) and Recovery Point Objective (RPO).

## Introduction

Application logs describe what happens inside a workload, but they may not show who changed the cloud infrastructure itself. Actions such as creating a user, granting administrator access, deleting a bucket, or changing a key are management-plane events. These events require separate monitoring, storage, alerting, and protection.

The second part of the lab tests resilience. A primary S3-compatible store is populated with data, copied to a separate DR bucket, deliberately damaged, and restored. The restore is timed so that the RTO is measured rather than guessed.

## Environment Preparation

LocalStack was started with request logging enabled:

~~~
docker rm -f localstack 2>/dev/null

docker run -d --name localstack -p 4566:4566 \
  -e DEBUG=1 \
  localstack/localstack:4.4.0
~~~

The health endpoint was checked before AWS CLI operations were started:

~~~
until curl -sf http://localhost:4566/_localstack/health >/dev/null; do
  sleep 2
done

export EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
~~~

The caller identity returned LocalStack account 000000000000 and the local root ARN, confirming that the commands were directed to the local simulator.

<img width="725" height="237" alt="image" src="https://github.com/user-attachments/assets/aee9fafb-f561-4aed-b879-3514476eb1b3" />

## Task A1: Reconstruct the Management-Plane Audit Trail

### A1.1 Create a Separate Audit Store

An S3 bucket was created for the management trail:

~~~
aws $EP s3api create-bucket --bucket miit-audit-trail

aws $EP s3api put-bucket-versioning \
  --bucket miit-audit-trail \
  --versioning-configuration Status=Enabled
~~~

The bucket represents a separate trust boundary. In production, the audit store should be owned by a separate account or security team so that an administrator in the audited account cannot silently delete or edit the evidence.

The observation baseline was recorded:

~~~
BEFORE=$(docker logs localstack 2>&1 | wc -l)
echo "baseline: $BEFORE lines"
~~~

The screenshot recorded a baseline of 74 LocalStack log lines.

<img width="767" height="185" alt="image" src="https://github.com/user-attachments/assets/505bf77e-dc5e-448c-95a2-55b7c6953a8f" />

### A1.2 Generate Administrative Activity

The following management-plane actions were generated:

~~~
aws $EP s3api create-bucket --bucket miit-throwaway

aws $EP iam create-user --user-name TempContractor

aws $EP iam attach-user-policy \
  --user-name TempContractor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws $EP s3api delete-bucket --bucket miit-throwaway
~~~

These operations change the cloud configuration or identity boundary rather than generating normal application traffic. The temporary user was granted administrator access and the throwaway bucket was deleted.

<img width="758" height="330" alt="image" src="https://github.com/user-attachments/assets/f808a1fe-6826-4fce-a63a-2c2fb556835d" />

### A1.3 Extract the Management Trail

The LocalStack request log was filtered from the baseline onward:

~~~
docker logs localstack 2>&1 | tail -n +$((BEFORE+1)) \
  | grep -E 'AWS [a-z0-9-]+\.[A-Za-z]+ => ' > mgmt-trail.log

wc -l mgmt-trail.log
~~~

The result contained four events. The relevant management events were filtered with:

~~~
grep -E \
  '\.(CreateUser|AttachUserPolicy|DeleteUser|CreateBucket|DeleteBucket|PutBucketPolicy|ScheduleKeyDeletion) =>' \
  mgmt-trail.log
~~~

The extracted trail showed:

| Service and operation | Status |
|---|---:|
| s3.CreateBucket | 200 |
| iam.CreateUser | 200 |
| iam.AttachUserPolicy | 200 |
| s3.DeleteBucket | 204 |

<img width="767" height="271" alt="image" src="https://github.com/user-attachments/assets/9913bbea-7d47-43cd-b62d-c52ab0526e22" />

### A1.4 Seal the Trail

The audit log was hashed with SHA-256:

~~~
sha256sum mgmt-trail.log > mgmt-trail.sha256
cat mgmt-trail.sha256
~~~

The recorded digest was:

~~~
cd2667b31175c33d72dd350e4dcb44841cc88dc76e0b2d87087702314df72d4
~~~

Both the log and the digest were uploaded to the audit bucket:

~~~
aws $EP s3 cp mgmt-trail.log s3://miit-audit-trail/
aws $EP s3 cp mgmt-trail.sha256 s3://miit-audit-trail/
~~~

<img width="762" height="80" alt="image" src="https://github.com/user-attachments/assets/6429ce94-e5e0-457e-a756-7c434f5dcf56" />

### A1.5 Detect Tampering

The AttachUserPolicy line was removed locally to simulate an attacker hiding the privilege escalation:

~~~
grep -v 'AttachUserPolicy' mgmt-trail.log > t.log \
  && mv t.log mgmt-trail.log
~~~

The original digest was downloaded from the audit bucket and used for verification:

~~~
aws $EP s3 cp s3://miit-audit-trail/mgmt-trail.sha256 ./check.sha256
sha256sum -c check.sha256
~~~

The output reported:

~~~
mgmt-trail.log: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
~~~

This proves that changing the log after it was sealed was detected.

<img width="767" height="235" alt="image" src="https://github.com/user-attachments/assets/9fceb9bb-b7f0-4d52-80d4-137be41ce11f" />

### What the Reconstruction Does Not Prove

The reconstructed line proves that a particular API operation occurred and gives its result, but it does not contain the full context of a real CloudTrail JSON event. Important fields that are missing include:

| Missing field | What it would establish |
|---|---|
| userIdentity and ARN | Which person, role, or service performed the action. |
| sourceIPAddress | Where the request originated and whether it matches another investigation. |
| eventTime | The exact time sequence of the action. |
| requestParameters | Which user, bucket, policy, or resource was changed. |
| eventID | A unique identifier for correlation across systems. |
| MFA/session information | Whether the identity used MFA or a temporary session. |

The sourceIPAddress field is especially useful during incident response. If the same address that brute-forced a login in Lab 5 also performed AttachUserPolicy, the two investigations become one correlated attack sequence: the source first attempted to obtain access and then used management-plane permissions to grant administrator access.

An administrator could defeat this local reconstruction by deleting or modifying the platform logs, stopping the logger, or editing both the trail and its local digest. A real deployment prevents this by sending immutable or append-only logs to a separate account, restricting delete permissions, validating log files, and alerting when management-plane logging is disabled.

## Task A2: Create a Primary Store and Separate Backup

Two buckets were created:

~~~
aws $EP s3api create-bucket --bucket miit-primary
aws $EP s3api create-bucket --bucket miit-dr-backup
~~~

Versioning was enabled on both:

~~~
aws $EP s3api put-bucket-versioning \
  --bucket miit-primary \
  --versioning-configuration Status=Enabled

aws $EP s3api put-bucket-versioning \
  --bucket miit-dr-backup \
  --versioning-configuration Status=Enabled
~~~

### A2.1 Create and Upload the Dataset

Two hundred small patient-record files were generated:

~~~
for i in $(seq 1 200); do
  echo "patient record $i - $(date)" > /tmp/rec$i.txt
done
~~~

The files were uploaded to the primary bucket:

~~~
aws $EP s3 sync /tmp/ s3://miit-primary/records/ \
  --exclude '*' --include 'rec*.txt'

aws $EP s3 ls s3://miit-primary/records/ | wc -l
~~~

The primary bucket contained **200 objects**.

<img width="761" height="237" alt="image" src="https://github.com/user-attachments/assets/e0e523dc-fe8c-4bbb-a845-babd09b607ab" />

<img width="767" height="206" alt="image" src="https://github.com/user-attachments/assets/9d07cdf2-1975-4d9f-93c9-55208b90cdcf" />

<img width="725" height="66" alt="image" src="https://github.com/user-attachments/assets/be6494f6-3f67-496c-be33-c67bcf5322de" />

### A2.2 Copy the Data to the DR Bucket

The primary bucket was copied to the separate backup bucket:

~~~
aws $EP s3 sync s3://miit-primary s3://miit-dr-backup
aws $EP s3 ls s3://miit-dr-backup/records/ | wc -l
~~~

The DR bucket also contained **200 objects**. The backup is a separate copy and therefore has a different trust and failure boundary from the primary bucket.

<img width="769" height="275" alt="image" src="https://github.com/user-attachments/assets/61ede458-d3a2-4ae3-a80d-2ca98b2fe245" />

<img width="756" height="108" alt="image" src="https://github.com/user-attachments/assets/e0f66299-5cc4-4f95-9440-d1d28d130e54" />

### Why Versioning Is Not a Backup

Versioning can survive an accidental overwrite or delete-marker operation because older object versions remain inside the same bucket. It does not necessarily survive deletion of the entire bucket, compromise of the account, deletion of all object versions by an administrator, or destruction of the encryption key. A separate backup bucket in another trust boundary can survive failures that affect the primary account or bucket.

## Task A3: Timed Restore Drill

### A3.1 Simulate the Incident

The primary records were deleted recursively:

~~~
aws $EP s3 rm s3://miit-primary/records/ --recursive
aws $EP s3 ls s3://miit-primary/records/ | wc -l
~~~

The result was **0 objects** in the visible primary path.

<img width="743" height="119" alt="image" src="https://github.com/user-attachments/assets/2299b2a4-bcc8-4577-8fc2-869fbc8e7686" />

<img width="740" height="91" alt="image" src="https://github.com/user-attachments/assets/26c5f12e-3d37-4c1d-8e46-a6f4a87ad890" />

### A3.2 Restore and Measure the RTO

The data was restored from the separate DR bucket while measuring elapsed time:

~~~
START=$(date +%s)
aws $EP s3 sync s3://miit-dr-backup s3://miit-primary
END=$(date +%s)

echo "Objects restored: $(aws $EP s3 ls \
  s3://miit-primary/records/ | wc -l)"
echo "MEASURED RTO (seconds): $((END - START))"
~~~

The evidence showed:

~~~
Objects restored: 200
MEASURED RTO (seconds): 3
~~~

The measured RTO for this 200-object local test dataset was therefore **3 seconds**.

<img width="764" height="109" alt="image" src="https://github.com/user-attachments/assets/2018a23c-dac6-45b1-afe4-4eb226e5ef3a" />

<img width="768" height="146" alt="image" src="https://github.com/user-attachments/assets/b2d12420-beff-476e-90ae-67b413ec547a" />

### RTO, Extrapolated RTO, and RPO

| Measure | Value | Explanation |
|---|---:|---|
| Measured RTO | **3 seconds** | Time to restore 200 objects in the recorded local test. |
| Extrapolated RTO for 1,000,000 objects | **15,000 seconds, approximately 4 hours 10 minutes** | Linear estimate: 1,000,000 / 200 × 3 seconds. This assumes identical object sizes, throughput, concurrency, network conditions, and no service throttling. |
| RPO | **Not recorded in the evidence** | RPO is the time between the last successful backup sync and the incident. Data written during that interval would be lost. |

The extrapolated value is only a rough planning estimate. Object size, API limits, parallelism, network throughput, retries, and provider throttling mean that real performance will not scale perfectly linearly. The least reliable assumption is linear scaling from 200 objects to one million objects.

RPO is improved by backing up more frequently because less recent data is exposed to loss. RTO is improved by making restoration faster through parallel transfers, larger capacity, optimized backup formats, tested automation, and a recovery design close to the required region or workload.

## Task A4: Compare Two Recovery Paths

The number of delete markers and object versions in the primary bucket was inspected:

~~~
aws $EP s3api list-object-versions \
  --bucket miit-primary \
  --prefix records/ \
  --query 'length(DeleteMarkers)'

aws $EP s3api list-object-versions \
  --bucket miit-primary \
  --prefix records/ \
  --query 'length(Versions)'
~~~

The recorded results were:

- Delete markers: **200**
- Object versions: **400**

This shows that versioned copies still existed under the delete markers in the primary bucket. The separate-backup path restored the same 200 visible records from miit-dr-backup.

<img width="748" height="129" alt="image" src="https://github.com/user-attachments/assets/cb84ee8e-d2f7-4b99-bab5-1afe16a4e55d" />

| Recovery question | Versioning in the primary bucket | Separate backup bucket |
|---|---|---|
| Recovery speed | Usually fast for individual objects because old versions are already in place. | Requires copying data back, so it may be slower, but it was measured at 3 seconds for 200 objects in this test. |
| Survives bucket deletion? | No. The versions are deleted with the bucket unless another copy exists. | Yes, if the backup bucket is separate and not deleted with the primary. |
| Survives compromised admin credentials? | Not necessarily. An administrator may delete object versions or disable protections. | Better protection when stored in a separate account with restricted access and immutable controls. |
| Survives cryptographic erasure of the KMS key? | No if the versions use the destroyed key. | No if the backup uses the same destroyed key; it requires an independent key strategy. |
| Cost profile | Additional storage for versions and delete markers in the primary environment. | Additional storage, transfer, monitoring, and management cost, but provides disaster-recovery separation. |

An incident that versioning may survive but a separate backup may not is an accidental deletion of one object when the backup has not yet synchronized the latest version. An incident that a separate backup may survive but versioning may not is deletion of the primary bucket or compromise of the primary account.

## Short-Answer Questions

### Q1. Name three administrative actions that may produce no application log.

1. **Attach an administrator policy to a user:** The attacker gains broad control over the account and may create persistence.
2. **Delete a bucket:** The attacker destroys stored data or disrupts a service without needing to interact with the application.
3. **Schedule deletion or disable an encryption key:** The attacker prevents decryption and can make protected data permanently unavailable.

Other examples include creating a new IAM user, changing a bucket policy, disabling logging, or deleting a backup.

### Q2. How do log validation, the digest, and a hash chain solve the same problem?

Each method calculates a cryptographic hash over data and later recalculates it to detect changes. If the current file does not produce the stored digest, the file was modified. The digest must be stored in a different trust boundary because an attacker with access to the audited account could otherwise edit both the log and its digest, making the alteration appear valid.

### Q3. Distinguish RTO and RPO.

RTO is the maximum acceptable time required to restore service or data after an incident. The measured RTO here was 3 seconds for 200 objects, with a rough linear extrapolation of approximately 4 hours 10 minutes for one million objects. RPO is the maximum acceptable amount of recent data loss, measured as the time since the last successful backup. The evidence did not record the exact sync-to-incident interval, so the RPO value cannot be calculated from the screenshots.

### Q4. Why should the measured 3-second RTO not be reported directly to a board?

It was measured on a small local dataset of only 200 small objects. A production dataset may contain millions of larger objects and may experience throttling, network delays, concurrency limits, retries, encryption overhead, and operational approval delays. The board should receive a tested production-scale estimate, a stated confidence range, assumptions, and the extrapolated result rather than the small-lab measurement alone.

### Q5. Compare an incident survived by versioning and one survived by a separate backup.

Versioning may survive an accidental overwrite or single-object delete because previous versions remain in the same bucket. A separate backup may survive deletion of the primary bucket or compromise of the primary account because the recovery copy exists in another trust boundary. Neither control automatically survives cryptographic erasure if the same encryption key protects both copies.

## Security Best-Practices Checklist

- [x] Management-plane activity was reconstructed from the platform request log.
- [x] The audit trail was stored in a separate audit bucket.
- [x] The trail was sealed with a SHA-256 digest.
- [x] Tampering was detected by checksum verification.
- [x] Primary and DR buckets were created separately.
- [x] Versioning was enabled on both buckets.
- [x] 200 objects were copied to the separate backup.
- [x] A destructive incident and restore were performed.
- [x] The restore was timed and produced a measured RTO of 3 seconds.
- [x] RPO was identified as the interval since the last backup sync.
- [x] Versioning and separate-backup recovery paths were compared.

## Conclusion

This lab demonstrated why management-plane auditing and tested recovery are essential parts of cloud security. The reconstructed trail captured four administrative events, including the privilege escalation of TempContractor, and the SHA-256 validation detected when the trail was edited. The primary S3 store was backed up to a separate DR bucket containing 200 objects. After the primary records were deleted, all 200 objects were restored in a measured 3 seconds. The exercise also showed that versioning is useful for recovering earlier object versions but is not a complete backup because it remains inside the same trust boundary. A reliable BCDR design must combine management-plane monitoring, protected audit storage, separate backups, measured RTO, defined RPO, and regular restore testing.

## Cleanup Commands

After the evidence has been saved, the lab resources can be removed:

~~~
aws $EP s3 rb s3://miit-dr-backup --force
aws $EP s3 rb s3://miit-audit-trail --force

aws $EP iam detach-user-policy \
  --user-name TempContractor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws $EP iam delete-user --user-name TempContractor

docker rm -f localstack
rm -f /tmp/rec*.txt mgmt-trail.log \
  mgmt-trail.sha256 check.sha256
~~~

