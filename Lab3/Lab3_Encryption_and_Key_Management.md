# Lab 3: Encryption and Key Management

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 0 - Environment Setup |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to protect data confidentiality, integrity, and availability using encryption and key-management techniques. The lab demonstrates symmetric AES encryption for data at rest, asymmetric RSA encryption and digital signatures, TLS encryption for data in transit, LocalStack KMS, envelope encryption, per-tenant keys, cryptographic erasure, hashing, and tamper-evident hash chains.

## Introduction

Encryption protects the confidentiality of data, but the strength of the protection depends on how cryptographic keys are generated, stored, distributed, rotated, and destroyed. This lab uses OpenSSL for hands-on cryptographic operations and LocalStack as a local AWS-compatible KMS environment. No real AWS account is required.

The activities are divided into two sessions:

1. **Session A:** Symmetric encryption, asymmetric encryption, signatures, and TLS.
2. **Session B:** KMS keys, envelope encryption, per-tenant keys, cryptographic erasure, and integrity verification.

## Task 1: Symmetric Encryption with AES

### 1.1 Create the Sensitive Record

A sample confidential patient record was created:

```bash
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt
```

The file represents sensitive data that must be protected while stored on disk.

### 1.2 Encrypt the File

The record was encrypted using AES-256-CBC with PBKDF2 key derivation and a random salt:

```bash
openssl enc -aes-256-cbc -pbkdf2 -salt \
  -in record.txt -out record.enc
```

OpenSSL prompted for an encryption passphrase. The passphrase acts as the shared secret key. When the encrypted file was displayed with `cat`, the output appeared as unreadable binary data rather than the original plaintext.

### 1.3 Decrypt and Verify the File

The encrypted file was decrypted using the same passphrase:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in record.enc -out record.dec.txt
```

The original and decrypted files were compared:

```bash
diff record.txt record.dec.txt && \
  echo 'MATCH: decryption successful'
```

The output was:

```text
MATCH: decryption successful
```

This proves that the encrypted data could be recovered when the correct key was supplied.

<img width="769" height="259" alt="1-Symmetric Encryption" src="https://github.com/user-attachments/assets/48d31669-51cc-4e77-ae5d-4cdab9920c14" />

### Symmetric-Key Distribution Problem

Symmetric encryption is fast and suitable for large files, but the sender and receiver must both possess the same secret key. The key must be distributed securely before the data is shared. If the key is sent through an insecure channel, an attacker can obtain it and decrypt the data. In a cloud environment with many users, services, and tenants, securely distributing and rotating shared keys becomes difficult. This is why a centralized KMS or asymmetric key exchange is important.

## Task 2: Asymmetric Encryption and Digital Signatures

### 2.1 Generate an RSA Key Pair

An RSA private key and corresponding public key were generated:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

The private key must remain secret. The public key can be shared with other parties.

### 2.2 Encrypt with the Public Key and Decrypt with the Private Key

The record was encrypted with the public key:

```bash
openssl pkeyutl -encrypt -pubin \
  -inkey public.pem -in record.txt -out record.rsa
```

Only the matching private key can decrypt the ciphertext:

```bash
openssl pkeyutl -decrypt -inkey private.pem \
  -in record.rsa -out record.rsa.txt
```

This provides confidentiality because anyone can use the public key to encrypt, but only the holder of the private key can decrypt.

### 2.3 Create and Verify a Digital Signature

The record was signed with the private key:

```bash
openssl dgst -sha256 -sign private.pem \
  -out record.sig record.txt
```

The signature was verified with the public key:

```bash
openssl dgst -sha256 -verify public.pem \
  -signature record.sig record.txt
```

The output was `Verified OK`. This confirms that the file was signed by the holder of the private key and that the file contents were not changed after signing.

<img width="768" height="233" alt="2-Asymmetric Encryption" src="https://github.com/user-attachments/assets/0041a9bc-e758-455c-8b3f-b86c8efe1b08" />

### Encryption and Signing Use Keys Differently

For encryption, the sender uses the recipient's public key and the recipient uses the private key to decrypt. For signing, the owner uses the private key to create the signature and others use the public key to verify it. The private key must therefore be carefully protected in both cases.

## Task 3: Encryption in Transit with TLS

### 3.1 Generate a Self-Signed Certificate

A temporary RSA certificate and private key were generated for `localhost`:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
```

The certificate is self-signed and intended for local testing. A production service should use a certificate issued by a trusted certificate authority.

<img width="958" height="341" alt="3-Generate sign signature" src="https://github.com/user-attachments/assets/0f103820-6c6d-4710-b4e1-40fb7508f060" />

### 3.2 Serve the Record over HTTPS

An Nginx container was started on host port 8443. The certificate, private key, and record were mounted into the container:

```bash
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  nginx
```

The record was requested over HTTPS:

```bash
curl -k https://localhost:8443/record.txt
```

The output returned the original record:

```text
Patient: Ahmad, Diagnosis: confidential
```

The `-k` option allows curl to accept the self-signed certificate for this local demonstration. TLS encrypts the traffic between the client and server, preventing an on-path attacker from reading the record in transit.

<img width="746" height="182" alt="3 1-https port 8443 small container   connect" src="https://github.com/user-attachments/assets/737ae99e-5288-4872-9906-f82643486a95" />

## Task 4: Create and Use a LocalStack KMS Key

The AWS CLI was pointed to LocalStack:

```bash
EP='--endpoint-url=http://localhost:4566'
```

A customer master key was created for tenant A:

```bash
aws $EP kms create-key \
  --description 'CCSE tenant-A master key'
```

The output showed an enabled key with description `CCSE tenant-A master key`, account `000000000000`, and key usage `ENCRYPT_DECRYPT`. The key ID was stored in a shell variable:

```bash
KEY_A=<PASTE_KEYID>
```

A small secret was encrypted directly with KMS:

```bash
aws $EP kms encrypt --key-id $KEY_A \
  --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

The command returned a ciphertext blob, confirming that KMS encryption was working.

<img width="788" height="543" alt="4-Create Use KMS Master Key" src="https://github.com/user-attachments/assets/c1dc27d3-25f0-481b-a718-4f88f66f60d5" />

## Task 5: Envelope Encryption

For large data, the master key should not encrypt every byte directly. Instead, envelope encryption uses a temporary data key:

1. KMS generates a plaintext data key and an encrypted copy of that data key.
2. The plaintext data key encrypts the large file locally.
3. The encrypted data key is stored with the ciphertext.
4. The plaintext data key is removed from local storage.

### 5.1 Generate a Data Key

```bash
aws $EP kms generate-data-key \
  --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text
```

The output contained a plaintext data key and a KMS-wrapped ciphertext version. The plaintext and wrapped values were saved separately for the demonstration.

### 5.2 Encrypt the File Locally

The plaintext data key was decoded and used with OpenSSL:

```bash
base64 -d datakey.b64 > datakey.bin

openssl enc -aes-256-cbc -pbkdf2 \
  -in record.txt -out record.env.enc \
  -pass file:./datakey.bin
```

### 5.3 Remove the Plaintext Data Key

After encryption, the plaintext key was removed:

```bash
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

The output confirmed that only the KMS-wrapped data key remained. This protects the large file with a local data key while the master key remains under KMS control.

<img width="823" height="308" alt="5-Envelope Encryption" src="https://github.com/user-attachments/assets/ef0a69ef-55a0-4300-9bbb-f98f476b74dd" />

### Why Envelope Encryption Is Useful

Envelope encryption is efficient because symmetric data-key encryption is fast for large files. The KMS master key only protects the small data key, so the master key does not need to process the entire data set. Hardware-grade protection is concentrated on the master key, while encrypted data keys can be stored alongside the encrypted files.

## Task 6: Per-Tenant Keys and Cryptographic Erasure

### 6.1 Create a Separate Tenant-B Key

A second KMS key was created for tenant B:

```bash
aws $EP kms create-key \
  --description 'CCSE tenant-B master key'
```

The key ID was stored separately:

```bash
KEY_B=<PASTE_KEYID>
```

The output showed a separate enabled customer key with description `CCSE tenant-B master key`. Using separate keys gives each tenant an independent cryptographic boundary.

<img width="824" height="399" alt="6-Per Tenant Key" src="https://github.com/user-attachments/assets/31265431-f5a1-4efc-a71e-34d5e5210669" />

### 6.2 Schedule Key Deletion and Disable the Key

The guide specifies a seven-day deletion window followed by immediate disabling:

```bash
aws $EP kms schedule-key-deletion \
  --key-id $KEY_A --pending-window-in-days 7

aws $EP kms disable-key --key-id $KEY_A
```

The screenshot shows LocalStack errors indicating that the key was already in a pending-deletion state when the commands were repeated. It also shows a decrypt attempt failing because `datakey.enc` was not available at the specified path. The intended security result is that, after the wrapping key is unavailable or destroyed, the encrypted data key cannot be unwrapped and the encrypted record cannot be recovered.

<img width="822" height="326" alt="6 1-Cryptographic Erasure" src="https://github.com/user-attachments/assets/3c20b479-0339-440d-83b4-daefebf90510" />

### Cryptographic Erasure

Deleting or destroying the key that wrapped a data key makes the encrypted data unrecoverable, even if the ciphertext remains on storage. This is cryptographic erasure. It is more practical in cloud environments than overwriting physical blocks because customers normally do not control the provider's underlying disks, replicas, snapshots, or backup media.

## Task 7: Integrity and Tamper Evidence

### 7.1 Fingerprint the Original File

The SHA-256 hash of the original record was calculated:

```bash
sha256sum record.txt
```

The original hash shown in the evidence was:

```text
9345a32351cc1ad03e8b318059b573ad6cde4325688da97a01599b32bc945dd5
```

### 7.2 Modify a Copy and Compare Hashes

A modified copy was created:

```bash
cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt
```

The hashes were different:

```text
9345a32351cc1ad03e8b318059b573ad6cde4325688da97a01599b32bc945dd5  record.txt
8c8afc8a3e34425ab38ef90211302c638a82f756bd7187a03b306c5683065eb7  tampered.txt
```

Even a small change caused a completely different digest. This provides evidence that the file contents were modified.

<img width="769" height="112" alt="7-Integrity" src="https://github.com/user-attachments/assets/93410652-84b5-4f56-90c8-12e4c788f360" />

### 7.3 Build a Hash Chain

The hash chain was created by including the previous hash in the input for the next record:

```bash
PREV=0
for line in 'login ok' 'file read' 'export data'; do \
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1); \
  echo "$line | $PREV"; \
done
```

The chain output was:

```text
login ok | 573f9f26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read | 8c39bacc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d
export data | e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68
```

Each entry depends on the previous hash. If an earlier entry changes, the following hashes no longer match, making the log tamper-evident.

<img width="726" height="146" alt="7 1-Tamper Evidence" src="https://github.com/user-attachments/assets/277b5913-e83f-4274-85f6-294f4edc4b43" />

## Verification Commands

The required verification commands are:

```bash
aws --endpoint-url=http://localhost:4566 kms list-keys

openssl dgst -sha256 -verify public.pem \
  -signature record.sig record.txt
```

The OpenSSL verification returned `Verified OK`, confirming the signature and file integrity.

## Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption.

Symmetric encryption uses one shared secret key for encryption and decryption. It is fast and suitable for large amounts of data, but securely distributing the shared key is difficult. Asymmetric encryption uses a public/private key pair. It is slower but solves many key-distribution problems because the public key can be shared openly. In practice, asymmetric cryptography is often used for key exchange and signatures, while symmetric encryption protects the actual data.

### Q2. Why is key management the weakest link?

Strong algorithms cannot protect data if keys are exposed, reused, stored insecurely, or never rotated. An attacker who obtains the key can decrypt protected data without breaking the encryption algorithm. Secure key storage, access control, rotation, auditing, backup, and destruction are therefore as important as the choice of algorithm.

### Q3. Explain envelope encryption.

Envelope encryption uses a data key to encrypt the actual file and a master key to encrypt, or wrap, the data key. The file is encrypted efficiently with the data key, while KMS protects the small wrapped key. The plaintext data key can be discarded after use, leaving only the ciphertext and KMS-wrapped copy. Hardware-grade protection is needed mainly for the master key.

### Q4. How does cryptographic erasure provide provable deletion?

When the key used to wrap or encrypt data is destroyed, the remaining ciphertext cannot be decrypted. This works even if copies remain in disks, snapshots, or backups. It is more reliable in the cloud than trying to overwrite physical blocks that the customer cannot directly control.

### Q5. How does a hash chain make a log tamper-evident?

Every log entry is hashed together with the previous entry's hash. Changing one entry changes its hash and invalidates every later link in the chain. A verifier can recalculate the chain and detect modification, insertion, or deletion of records.

## Security Best-Practices Checklist

- [x] Data at rest was encrypted with AES and decryption was verified.
- [x] RSA public/private keys were used for encryption and decryption.
- [x] A digital signature was created and verified with `Verified OK`.
- [x] Data in transit was protected with HTTPS/TLS.
- [x] Envelope encryption was demonstrated.
- [x] The plaintext data key was removed from disk after use.
- [x] Separate KMS keys were created for tenant A and tenant B.
- [x] Cryptographic erasure and failed key/data recovery were demonstrated as far as supported by the recorded output.
- [x] File integrity was checked using SHA-256 hashes.
- [x] A tamper-evident hash chain was created.

## Conclusion

This lab demonstrated a complete set of data-protection controls. AES provided efficient encryption for data at rest, while RSA supported public-key encryption and digital signatures. TLS protected the patient record while it was transmitted over HTTPS. LocalStack KMS was then used to create tenant-specific keys and support envelope encryption, where only the wrapped data key remained after local cleanup. Finally, SHA-256 detected file modification and a hash chain made a sequence of records tamper-evident. The exercises show that encryption algorithms, secure key management, access control, and integrity verification must work together to protect cloud data.

## Cleanup Commands

After completing the report, the temporary resources can be removed:

```bash
docker stop tls 2>/dev/null
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt
docker stop localstack && docker rm localstack
```

