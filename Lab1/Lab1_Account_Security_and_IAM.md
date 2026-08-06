# Lab 1: Account Security and IAM

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 0 - Environment Setup |
| **Name** | MUHAMMAD HAFEEZ BIN MOHD RADZI |
| **Student ID** | 52215226085 |

## Objective

The objective of this lab is to understand and apply cloud identity and access-management security principles using LocalStack and Kubernetes. The lab demonstrates how to replace root-user activity with dedicated identities, manage permissions through groups and policies, apply least privilege to a read-only user, handle access-key rotation, and enforce role-based access control (RBAC) in Kubernetes. The tests also show the difference between authentication, which verifies an identity, and authorization, which determines what that identity is allowed to do.

## Introduction

LocalStack was used as a local AWS-compatible simulator, so no real AWS account or cloud resources were required. AWS CLI commands were sent to `http://localhost:4566`. Kubernetes was run locally through kind inside Docker.

The lab was completed in two parts:

1. **Session A:** LocalStack IAM users, groups, policies, and access keys.
2. **Session B:** Kubernetes namespaces, Roles, RoleBindings, and authorization tests.

## Task 1: Cloud Identity Landscape

| Identity concept | AWS term | Purpose |
|---|---|---|
| All-powerful owner | Root user | The original account identity with complete control over the AWS account. It should be protected and avoided for daily work. |
| Human or application identity | IAM User | A named, long-term identity that can authenticate and receive permissions. |
| Permission bundle | IAM Policy | A document that defines which actions are allowed or denied on specified resources. |
| Collection of users | IAM Group | A manageable collection of IAM users that receive common permissions through group policies. |
| Temporary identity | IAM Role | An identity that can be assumed temporarily to obtain permissions without using permanent credentials. |

The main security principle is to use the smallest practical permissions for each identity and avoid using the root user for ordinary operations.

## Environment Setup

The AWS CLI was configured with dummy LocalStack credentials and a local endpoint variable:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
```

The returned account was `000000000000`, confirming that the command was sent to LocalStack rather than a real AWS account. The returned ARN identified the current operating identity as the LocalStack root identity.

<img width="647" height="178" alt="1-test talk to localstack" src="https://github.com/user-attachments/assets/a989c7c2-161c-4659-9a24-e9823d890891" />

## Task 2: Create a Least-Privilege Admin

### 2.1 Create the Admins Group and Attach a Policy

The `Admins` group was created first. The AdministratorAccess policy was attached to the group rather than directly to an individual user:

```bash
aws $EP iam create-group --group-name Admins

aws $EP iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Attaching the policy to a group makes permission management easier. If the policy needs to be changed, it can be updated once for all group members.

### 2.2 Create the Dedicated Admin User

A named administrative user was created:

```bash
aws $EP iam create-user --user-name CloudAdmin_Hafeez
```

The user was added to the `Admins` group:

```bash
aws $EP iam add-user-to-group \
  --group-name Admins \
  --user-name CloudAdmin_Hafeez
```

The group membership was verified with:

```bash
aws $EP iam get-group --group-name Admins
```

The output showed `CloudAdmin_Hafeez` as a member of the `Admins` group. The administrative permissions therefore flow from the group policy instead of being attached directly to the user.

<img width="714" height="776" alt="2-create group and make it admin" src="https://github.com/user-attachments/assets/b74246c3-61e9-4745-9112-b06e0f24fb66" />

## Task 3: Enforce Least Privilege with a Scoped Policy

A separate Analyst user was created for read-only work:

```bash
aws $EP iam create-user --user-name Analyst_Riven

aws $EP iam attach-user-policy \
  --user-name Analyst_Riven \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

The attached policy was checked with:

```bash
aws $EP iam list-attached-user-policies \
  --user-name Analyst_Riven
```

The result showed only `AmazonS3ReadOnlyAccess`. This user can perform permitted read-only S3 actions but cannot modify or delete S3 data through that policy.

<img width="790" height="380" alt="3-create least privileges user" src="https://github.com/user-attachments/assets/6b6ff780-8a18-4905-8864-039089606ccf" />

### Blast-Radius Reduction

If the Analyst account were stolen, the attacker would have a smaller blast radius than an attacker using the administrator identity. The Analyst has only the permissions included in the read-only policy, so the attacker should not be able to administer IAM, create new users, change permissions, or modify protected data through this identity. Least privilege limits the possible damage and makes an incident easier to contain.

## Task 4: Credential Hygiene and Access Keys

An access key was created for the Analyst user to demonstrate programmatic access:

```bash
aws $EP iam create-access-key --user-name Analyst_Riven
```

The access-key metadata was listed:

```bash
aws $EP iam list-access-keys --user-name Analyst_Riven
```

The screenshot shows the key with status `Active`. Access keys are sensitive long-lived credentials and must not be exposed, committed to source control, or placed in reports in an unredacted form.

<img width="761" height="378" alt="4-create access key" src="https://github.com/user-attachments/assets/c4acb4f7-9bed-4e4f-82dc-259f49f69996" />

The old key was then rotated by setting its status to `Inactive`:

```bash
aws $EP iam update-access-key \
  --user-name Analyst_Riven \
  --access-key-id <PASTE_KEY_ID> \
  --status Inactive

aws $EP iam list-access-keys --user-name Analyst_Riven
```

The final output showed the access key as `Inactive`. Deactivating an old key is safer than leaving an unused credential active. In real AWS environments, short-lived role credentials are preferred where possible.

<img width="728" height="235" alt="4 1-update access key" src="https://github.com/user-attachments/assets/7eb74a93-4948-45b6-9ffd-95e61627ffa6" />

## Task 5: Create a Local Kubernetes Cluster

A local Kubernetes cluster named `ccse-lab1` was created using kind:

```bash
kind create cluster --name ccse-lab1
```

The cluster was checked with:

```bash
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

The control-plane node `ccse-lab1-control-plane` was shown as `Ready`, confirming that the cluster was operational.

<img width="798" height="439" alt="5-create local kubernetes cluster" src="https://github.com/user-attachments/assets/577f2eab-5eeb-4152-83ae-206265475ea7" />

## Task 6: Separate Environments with Namespaces

Two namespaces were created to separate development and production resources:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

The output showed both `dev` and `prod` with status `Active`. Namespaces provide an important boundary for organizing workloads and applying namespace-scoped permissions.

<img width="576" height="263" alt="6-separate env with namespaces" src="https://github.com/user-attachments/assets/acc2eca9-4dd6-442c-8d00-2a4756d1003f" />

## Task 7: Define a Role and Bind It

A service account was created to represent a developer in the `dev` namespace:

```bash
kubectl create serviceaccount dev-user -n dev
```

A namespaced Role named `pod-reader` was created with only the `get`, `list`, and `watch` permissions for pods:

```bash
kubectl create role pod-reader -n dev \
  --verb=get,list,watch \
  --resource=pods
```

The Role was bound to the `dev-user` service account:

```bash
kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader \
  --serviceaccount=dev:dev-user
```

This implements RBAC using two parts:

- A **Role** defines the permissions and resources.
- A **RoleBinding** assigns those permissions to a user or service account.

<img width="734" height="165" alt="7-define role and bind" src="https://github.com/user-attachments/assets/406d05e9-0383-4597-956c-ed2a5fca2b4c" />

## Access-Control Test

The service account identity was assigned to a shell variable:

```bash
SA=system:serviceaccount:dev:dev-user
```

The following authorization checks were performed:

```bash
kubectl auth can-i list pods -n dev --as=$SA
kubectl auth can-i delete pods -n dev --as=$SA
kubectl auth can-i list pods -n prod --as=$SA
```

The results were:

| Request | Result | Explanation |
|---|---|---|
| List pods in `dev` | `yes` | The Role grants `list` on pods in the `dev` namespace. |
| Delete pods in `dev` | `no` | The Role does not grant the `delete` verb. |
| List pods in `prod` | `no` | The Role is namespaced to `dev` and does not apply to `prod`. |

<img width="708" height="162" alt="8-test access control" src="https://github.com/user-attachments/assets/e86c1f35-f4b1-404f-88e2-7913cecf6515" />

### Authentication versus Authorization

The service account passes authentication because Kubernetes recognizes the identity `system:serviceaccount:dev:dev-user`. Authorization is then evaluated against the Role and RoleBinding. The delete request is blocked because `delete` is not an allowed verb, and the production request is blocked because the Role has scope only in the `dev` namespace.

## RBAC Verification Command

The RoleBinding was inspected using the required verification command:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

The YAML output confirmed that:

- The resource is a `RoleBinding`.
- The namespace is `dev`.
- The referenced Role is `pod-reader`.
- The subject is the `dev-user` ServiceAccount in the `dev` namespace.

<img width="734" height="303" alt="9-verification command" src="https://github.com/user-attachments/assets/b447306e-ff74-4dd1-ac13-209d8ebee30c" />

## Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?

Groups make permission management consistent and scalable. A policy can be attached once to a group, and all members receive the same permissions. Removing a user from the group also removes the group permissions. This improves auditing and reduces inconsistent direct permissions.

### Q2. What is the difference between an IAM User and an IAM Role?

An IAM User is a named identity normally associated with a person or application and may have long-term credentials. An IAM Role is an assumable identity that provides temporary credentials. Roles are generally safer for workloads and temporary access because they avoid storing permanent access keys.

### Q3. How does the Analyst account demonstrate least privilege?

The Analyst user has only `AmazonS3ReadOnlyAccess`. It can read permitted S3 resources but is not granted administrative or write permissions. If compromised, the account has a smaller blast radius because the attacker cannot use it to manage identities, alter policies, or modify data through the attached policy.

### Q4. What is the difference between a Role and a RoleBinding in Kubernetes?

A Role describes the allowed actions, such as `get`, `list`, and `watch` on pods. A RoleBinding connects that Role to a subject such as a user or ServiceAccount. The Role alone does not grant access until it is bound to an identity.

### Q5. Why did the developer ServiceAccount fail to access prod?

The `dev-user` ServiceAccount was bound to a Role in the `dev` namespace. Kubernetes Roles are namespace-scoped, so the permissions did not extend to `prod`. This demonstrates least privilege and the principle of denying access outside the identity's required scope.

## Security Best-Practices Checklist

- [x] A dedicated admin identity was created instead of using root for daily tasks.
- [x] Administrator permissions were granted through the `Admins` group.
- [x] A least-privilege read-only Analyst identity was created.
- [x] The Analyst access key was listed and later deactivated.
- [x] Kubernetes RBAC allowed reading pods in `dev` but blocked deletion and `prod` access.
- [x] The RoleBinding was verified using YAML output.

## Cleanup Commands

The lab resources can be removed after the report is complete:

```bash
kind delete cluster --name ccse-lab1
docker stop localstack
docker rm localstack
```

## Conclusion

This lab successfully demonstrated identity governance and least-privilege access control. In LocalStack, an administrator was managed through a group, while the Analyst identity received only an S3 read-only policy. Access-key rotation was also demonstrated by changing the key status from `Active` to `Inactive`. In Kubernetes, namespaces separated `dev` and `prod`, and a namespaced Role allowed the developer ServiceAccount to read pods without permitting deletion or access to production. These results show how groups, policies, roles, bindings, and credential hygiene reduce unauthorized access and limit the impact of compromised credentials.


