# Lab 6: Object Storage Security and Data Lifecycle

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 6 – Object Storage Security and the Data Security Lifecycle |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to secure object storage throughout the data security lifecycle. The lab demonstrates data classification, public-bucket exposure, Block Public Access, least-privilege resource policies, IAM versus resource-based authorization, SSE-KMS encryption, presigned URLs, versioning, data remanence, lifecycle retention, and cryptographic erasure using LocalStack.

## Introduction

Object storage uses buckets and object keys, so its security model differs from block or file storage. Access can be controlled by IAM policies, bucket policies, ACLs, public-access guardrails, encryption settings, and lifecycle rules.

The lab was completed in two sessions:

1. Session A: classification, public exposure, remediation, and policy evaluation.
2. Session B: SSE-KMS, delegated access, versioning, lifecycle management, and erasure.

## Environment Setup

A clean LocalStack instance was started with IAM enforcement enabled:

~~~
docker rm -f localstack 2>/dev/null
docker run -d --name localstack -p 4566:4566 \
  -e ENFORCE_IAM=1 \
  localstack/localstack:4.4.0

export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
aws $EP sts get-caller-identity
~~~

The caller identity returned the LocalStack account 000000000000.

<img width="670" height="295" alt="image" src="https://github.com/user-attachments/assets/67f8b261-5c8f-4fa4-bc91-9f4c2d0f5a40" />

## Task 1: Data Classification

### 1.1 Create the Bucket and Objects

The patient-records bucket was created:

~~~
export BUCKET=miit-patient-records-4419
aws $EP s3api create-bucket --bucket $BUCKET

echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' \
  > confidential-record.txt
~~~

The evidence shows bucket miit-patient-records-4419.

<img width="721" height="218" alt="image" src="https://github.com/user-attachments/assets/89877c6e-01f3-4d09-8eb4-7567df5a8018" />

Each object was uploaded with a classification tag:

~~~
aws $EP s3api put-object --bucket $BUCKET \
  --key public/notice.txt --body public-notice.txt \
  --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET \
  --key internal/roster.txt --body internal-roster.txt \
  --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record.txt --body confidential-record.txt \
  --tagging 'classification=confidential'

aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key,Size]' --output table

aws $EP s3api get-object-tagging --bucket $BUCKET \
  --key confidential/record.txt
~~~

The object list contained public/notice.txt, internal/roster.txt, and confidential/record.txt. The confidential object was tagged classification=confidential.

<img width="822" height="452" alt="image" src="https://github.com/user-attachments/assets/03bdf211-a251-42fc-89c8-7b913ea82900" />
<img width="823" height="342" alt="image" src="https://github.com/user-attachments/assets/cd85ba3e-3bdd-40a9-869d-febb568bf15a" />

| Classification | Who may read it | Impact if leaked | Control |
|---|---|---|---|
| Public | Anyone when intentionally published | Low | Limited public prefix and classification tag |
| Internal | Authorized staff and services | Medium | Account-only policy scoped to internal/ |
| Confidential | Approved healthcare staff or services | High | No anonymous access, least privilege, SSE-KMS, versioning, lifecycle, and controlled deletion |

Object prefixes are not folders. The slash is part of the object key, so a broad wildcard can expose more data than intended.

## Task 2: Reproduce the Public-Bucket Breach

An unsafe bucket policy was created:

~~~
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET --policy file://public-policy.json
~~~

The anonymous read was tested:

~~~
curl -s -o leaked.txt \
  -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
~~~

The result was HTTP 200 and the confidential patient record was printed. The single policy element that caused the exposure was Principal: *. It allowed every principal, including anonymous callers.

<img width="822" height="485" alt="image" src="https://github.com/user-attachments/assets/9ec6c54b-72f4-4af9-b552-a3e0ef6672e6" />
<img width="712" height="113" alt="image" src="https://github.com/user-attachments/assets/fdd9fffb-408a-49ab-be28-83f75953cc3a" />

## Task 3: Block Public Access and Least Privilege

The unsafe policy was removed and all four public-access flags were enabled:

~~~
aws $EP s3api delete-bucket-policy --bucket $BUCKET

aws $EP s3api put-public-access-block \
  --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws $EP s3api get-public-access-block --bucket $BUCKET
~~~

The evidence showed all flags as true. However, reintroducing the public policy still succeeded and the anonymous request returned HTTP 200. This is the LocalStack limitation described in the guide. On real AWS, BlockPublicPolicy would reject the public policy and RestrictPublicBuckets would restrict access from public or cross-account policies.

A preventative guardrail is stronger than a detective control because it blocks the unsafe change before exposure rather than reporting it afterward.

<img width="822" height="361" alt="image" src="https://github.com/user-attachments/assets/7fba6ac5-2442-481e-83e8-17548cd3adbe" />

A least-privilege policy was created for account-only reads of the internal prefix:

~~~
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::000000000000:root"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET --policy file://least-privilege-policy.json
~~~

<img width="820" height="477" alt="image" src="https://github.com/user-attachments/assets/64aa5bf1-6cd9-476c-adcc-01d47b87e1b2" />

## Task 4: IAM and Resource-Based Authorization

The DataAnalyst user was created with a broad IAM read policy:

~~~
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy \
  --user-name DataAnalyst --policy-name S3ReadAll \
  --policy-document file://analyst-iam.json

aws $EP iam create-access-key --user-name DataAnalyst
~~~

<img width="761" height="416" alt="image" src="https://github.com/user-attachments/assets/1b3b7fb9-0bb6-44fd-b9ef-f874a8a0f246" />
<img width="821" height="199" alt="image" src="https://github.com/user-attachments/assets/5f9db657-6a03-4143-aea3-2511c40e9773" />

The bucket policy was then intended to allow internal reads but explicitly deny confidential reads:

~~~
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:user/DataAnalyst"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:user/DataAnalyst"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET --policy file://deny-confidential.json
~~~

Expected results:

| Request | Result | Reason |
|---|---|---|
| Analyst reads internal/roster.txt | Allowed | Both policies allow it. |
| Analyst reads confidential/record.txt | Denied | Explicit resource-policy Deny overrides IAM Allow. |

The screenshot shows object output for both requests and does not show the expected denial. Therefore, LocalStack did not fully enforce the explicit deny in the recorded run. The correct cloud evaluation is default deny, explicit deny, then applicable allow.

<img width="821" height="434" alt="image" src="https://github.com/user-attachments/assets/d56b2a1f-af7c-414e-b7ba-6fe8d3b3044e" />
<img width="866" height="542" alt="image" src="https://github.com/user-attachments/assets/85d7d1a5-0844-4a4f-90be-813f7c53ae29" />

The policy was removed before continuing:

~~~
aws $EP s3api delete-bucket-policy --bucket $BUCKET
~~~

## Task 5: Default SSE-KMS Encryption

A dedicated KMS key was created:

~~~
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID
~~~

The recorded key ID was 722b2536-403c-4ee7-adfc-e52621bde51c.

Default SSE-KMS encryption was configured:

~~~
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

aws $EP s3api put-bucket-encryption \
  --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json
~~~

<img width="820" height="578" alt="image" src="https://github.com/user-attachments/assets/720e3ed1-2412-4b89-8d23-923429924572" />

A new object was uploaded without encryption flags:

~~~
aws $EP s3api put-object \
  --bucket $BUCKET --key confidential/record-v2.txt \
  --body confidential-record.txt

aws $EP s3api head-object \
  --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' \
  --output text
~~~

The output confirmed aws:kms, the configured key ARN, and True for BucketKeyEnabled.

<img width="867" height="285" alt="image" src="https://github.com/user-attachments/assets/f5190ea6-e954-4a9e-8096-63941deaf825" />

SSE-KMS protects data at rest, but it does not replace authorization. An analyst who is authorized to read the object can still receive decrypted plaintext.

## Task 6: Presigned URLs and Secure Transport

### 6.1 Presigned URL

A time-limited URL was generated:

~~~
aws $EP s3 presign \
  s3://$BUCKET/internal/roster.txt --expires-in 60

URL='PASTE_PRESIGNED_URL_HERE'
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"
~~~

The URL returned the staff schedule with HTTP 200. The signed parameters bind the request to an algorithm, credential, timestamp, expiry, signed headers, and signature. Anyone holding the URL before expiry is authorized for that specific action and object.

<img width="865" height="231" alt="image" src="https://github.com/user-attachments/assets/a79c76c8-d614-4cd0-acaf-dcd287abda23" />

After 65 seconds the same URL was tested:

~~~
sleep 65
curl -s -o /dev/null \
  -w 'after expiry: HTTP %{http_code}\n' "$URL"
~~~

The evidence showed HTTP 200 after expiry. The guide identifies this as a LocalStack limitation; real S3 should reject the URL after the X-Amz-Expires period.

<img width="867" height="344" alt="image" src="https://github.com/user-attachments/assets/4c350a0b-43c1-40a0-82d1-d90c026d28c2" />

### 6.2 Secure Transport Condition

A policy was created to deny non-TLS requests:

~~~
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::$BUCKET",
      "arn:aws:s3:::$BUCKET/*"
    ],
    "Condition": {
      "Bool": {"aws:SecureTransport": "false"}
    }
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET --policy file://secure-transport.json
~~~

The lab endpoint is HTTP, so aws:SecureTransport is false for these requests. On real AWS the endpoint is HTTPS and the condition catches genuinely insecure callers. A policy must always be evaluated in its actual runtime environment. The policy was deleted before continuing:

~~~
aws $EP s3api delete-bucket-policy --bucket $BUCKET
~~~

<img width="869" height="793" alt="image" src="https://github.com/user-attachments/assets/51c02ceb-1c74-47de-aeeb-7f42d58fb0f1" />

## Task 7: Versioning and Data Remanence

Versioning was enabled:

~~~
aws $EP s3api put-bucket-versioning \
  --bucket $BUCKET \
  --versioning-configuration Status=Enabled
~~~

Two additional revisions were uploaded:

~~~
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object \
  --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object \
  --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

aws $EP s3api list-object-versions \
  --bucket $BUCKET --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
~~~

The version list showed the redacted version, the previous version, and the original pre-versioning object with version ID null.

<img width="835" height="166" alt="image" src="https://github.com/user-attachments/assets/b9a6b372-90cd-485e-a264-ae3ac1e00a6b" />
<img width="862" height="305" alt="image" src="https://github.com/user-attachments/assets/e2880535-a5dc-4619-a775-0bef8a5d506c" />

The current object was deleted:

~~~
aws $EP s3api delete-object \
  --bucket $BUCKET --key confidential/record.txt

aws $EP s3api list-object-versions \
  --bucket $BUCKET --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table
~~~

An ordinary read returned NoSuchKey, but the original version was recovered:

~~~
aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt
~~~

The recovered content was Patient: Ahmad bin Ali, Diagnosis: confidential.

<img width="866" height="650" alt="image" src="https://github.com/user-attachments/assets/10577958-05f3-4638-80ce-365b486a533f" />

This proves object-level data remanence. Delete-object alone does not remove older versions.

The original null version was then deleted by ID:

~~~
aws $EP s3api delete-object \
  --bucket $BUCKET --key confidential/record.txt \
  --version-id null

aws $EP s3api list-object-versions \
  --bucket $BUCKET --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,Size]' --output table
~~~

<img width="819" height="252" alt="image" src="https://github.com/user-attachments/assets/3be155fb-b3b9-4848-a7a3-094bee8df7cf" />

## Task 8: Lifecycle and Cryptographic Erasure

### 8.1 Lifecycle Policy

The retention policy was created:

~~~
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 7
      }
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table
~~~

| Rule | Status | Purpose |
|---|---|---|
| RetireConfidentialRecords | Enabled | Current objects expire after 365 days and noncurrent versions after 30 days. |
| AbortIncompleteUploads | Enabled | Incomplete multipart uploads expire after 7 days. |

<img width="836" height="600" alt="image" src="https://github.com/user-attachments/assets/9b7dca34-a614-4d98-b491-121318205eab" />

### 8.2 Disable and Schedule KMS Key Deletion

~~~
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text

aws $EP kms disable-key --key-id $KEY_ID

aws $EP kms schedule-key-deletion \
  --key-id $KEY_ID --pending-window-in-days 7

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
~~~

The final state was PendingDeletion with a seven-day window.

<img width="868" height="289" alt="image" src="https://github.com/user-attachments/assets/92ab1b2d-fa49-438a-86ae-7291478aaf21" />

The encrypted object was then read:

~~~
aws $EP s3api get-object \
  --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
~~~

LocalStack still returned the object. The guide identifies this as a simulator limitation because the S3 read did not re-check the disabled KMS key. In real AWS, destruction of the KMS key would make ciphertext protected by that key unrecoverable.

<img width="865" height="362" alt="image" src="https://github.com/user-attachments/assets/87ff9af1-2a47-4bfc-83d8-ee45b947e951" />

## Final Verification

~~~
aws $EP s3api get-public-access-block \
  --bucket $BUCKET --output text

aws $EP s3api get-bucket-versioning \
  --bucket $BUCKET --output text

aws $EP s3api get-bucket-encryption \
  --bucket $BUCKET --output text

aws $EP s3api get-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output text

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.KeyState' --output text
~~~

The recorded final output confirmed:

- All four public-access flags were True.
- Versioning was Enabled.
- Default encryption was aws:kms using key 722b2536-403c-4ee7-adfc-e52621bde51c.
- Both lifecycle rules were Enabled.
- The key state was PendingDeletion.

<img width="867" height="343" alt="image" src="https://github.com/user-attachments/assets/b9538daa-819f-43c0-9bbc-32489e145c25" />

## Short-Answer Questions

### Q1. Which policy element caused the exposure?

Principal: * caused the exposure because it allowed any principal to read every object. It is especially dangerous in a resource policy because it applies directly to the shared bucket and can authorize anonymous access.

### Q2. Explain IAM and resource policies.

An IAM policy is attached to a user, group, or role. A resource policy is attached to the bucket. The IAM policy gave DataAnalyst broad read permission, while the bucket policy was intended to allow only internal objects and explicitly deny confidential objects. An explicit Deny overrides an Allow. LocalStack did not fully enforce the deny in the supplied evidence.

### Q3. Why is Block Public Access a guardrail?

It prevents unsafe public configurations, while a detective control only reports them after they exist. A preventative guardrail is important when many engineers can create or edit buckets because it reduces the chance of exposure.

### Q4. Does SSE-KMS protect the confidential object from the analyst?

No. SSE-KMS protects stored data, but an authorized S3 reader receives decrypted content. IAM and bucket policies must restrict the analyst.

### Q5. Why is delete-object alone insufficient?

With versioning enabled, delete-object creates a delete marker and leaves previous versions. The original confidential diagnosis was recovered through the null version. Complete deletion requires removing every version and delete marker or destroying the KMS key that protects every copy.

### Q6. Which commands provide compliance evidence?

get-public-access-block proves public-access controls. get-bucket-encryption and head-object prove SSE-KMS. get-bucket-versioning proves versioning. get-bucket-lifecycle-configuration proves retention rules. kms describe-key proves key state. list-object-versions proves whether deleted data remains.

## Security Checklist

- [x] Objects were classified before access decisions.
- [x] Public-bucket exposure was reproduced.
- [x] All four Block Public Access flags were enabled.
- [x] Least-privilege access was scoped to an object prefix.
- [x] IAM and resource-policy authorization were compared.
- [x] Default SSE-KMS encryption was configured.
- [x] Encryption was verified with head-object.
- [x] A presigned URL was used for delegated access.
- [x] Versioning and data remanence were demonstrated.
- [x] Lifecycle rules were configured.
- [x] KMS key deletion was scheduled.
- [x] LocalStack enforcement limitations were documented.

## Conclusion

This lab demonstrated the security lifecycle of object storage. A public bucket policy exposed a confidential record through an anonymous request. Block Public Access and a least-privilege prefix policy provided the intended remediation. IAM and resource policies must be evaluated together, with explicit denies taking precedence over allows.

Default SSE-KMS protected new objects at rest, while a presigned URL provided limited delegated access. Versioning demonstrated data remanence because the original record remained recoverable after a normal delete. Lifecycle rules automated retention, and KMS key deletion demonstrated cryptographic erasure as the strongest practical way to make encrypted cloud data unrecoverable.

## Cleanup

A versioned bucket requires removal of all versions and delete markers before deletion:

~~~
aws $EP s3api delete-bucket-policy --bucket $BUCKET

aws $EP s3api delete-objects \
  --bucket $BUCKET \
  --delete "$(aws $EP s3api list-object-versions \
    --bucket $BUCKET --output json \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

aws $EP s3api delete-objects \
  --bucket $BUCKET \
  --delete "$(aws $EP s3api list-object-versions \
    --bucket $BUCKET --output json \
    --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

aws $EP s3api delete-bucket --bucket $BUCKET
aws $EP iam delete-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst
docker rm -f localstack
rm -f *.json *.txt
~~~

