# 1. Understanding AWS Privilege Escalation (High-Level)

Privilege escalation in AWS typically happens when excessive or misconfigured IAM permissions allow a principal to gain higher privileges than intended. Common **risk patterns** include:

### 1.1 IAM Misconfigurations

* IAM roles that allow **sts:AssumeRole** without proper trust restrictions.
* IAM users/roles with permissions to **modify their own policies** or **attach privileged policies**.
* Overly permissive policies (`"Effect": "Allow", "Action": "*", "Resource": "*"`).

### 1.2 Resource-Level Escalation Paths

* Lambda functions or EC2 instances with attached IAM roles that can be modified or replaced.
* Access to create or update IAM roles/service-linked roles.
* Ability to update CloudFormation stacks that deploy privileged roles.
* Permission to modify SSM Run Command documents.

### 1.3 Credential Exposure Risks

* Access keys stored in S3 buckets, EBS snapshots, AMIs, Git repos, or logs.
* Instance profile credentials accessible via EC2 metadata (if instance compromised).

---

# 2. How to Detect Privilege Escalation Risks Using **Prowler**

**Prowler** is an open-source AWS security auditing tool. It focuses on misconfigurations, compliance checks, and privilege escalation detection.

### 2.1 Install Prowler

```bash
git clone https://github.com/prowler-cloud/prowler
cd prowler
```

Run using AWS CLI credentials or a role with read-only permissions.

### 2.2 Run Prowler for IAM / Privilege Escalation Checks

Prowler has built-in checks for:

* IAM privilege escalation paths
* IAM policies
* Role trust relationships
* Over-permissive privileges

Run a full audit:

```bash
./prowler -A <AWS_PROFILE>
```

Run only IAM-related checks:

```bash
./prowler -A <AWS_PROFILE> -g iam
```

Generate full output in JSON or CSV:

```bash
./prowler -A <AWS_PROFILE> -M json -o output/
```

### 2.3 Key Prowler Checks Related to Privilege Escalation

Look for checks such as:

* **IAM-01**: Avoid use of root credentials.
* **IAM-03**: Ensure MFA is enabled.
* **IAM-15**: IAM policies should not allow full `*:*` permissions.
* **IAM-56 / IAM-57**: Detect dangerous IAM permissions (e.g., `iam:PassRole`, `sts:AssumeRole`).
* **IAM-59 / IAM-60**: Trust policy misconfigurations.

These highlight where AWS principals could escalate privileges.

---

# 3. Mitigation Strategies (Best Practices)

Below is a formal, cloud-security-architecture-oriented mitigation plan.

---

## 3.1 IAM Hardening

### Enforce Least Privilege

* Replace wildcard actions/resources with **explicit** permissions.
* Split roles for workloads into granular privilege sets.
* Use IAM Access Analyzer to detect external access or risky grants.

### Block Self-Modification Paths

Remove these permissions unless explicitly required:

* `iam:PutUserPolicy`
* `iam:AttachUserPolicy`
* `iam:CreateAccessKey`
* `iam:PassRole`
* `iam:UpdateAssumeRolePolicy`

### Restrict `sts:AssumeRole`

* Explicitly specify trusted principals.
* Add IAM condition blocks:

  ```json
  "Condition": {
    "StringEquals": {
      "aws:PrincipalArn": "<approved-role>"
    }
  }
  ```

---

## 3.2 Identity Governance Controls

* Require MFA for all users.
* Disable all IAM users if possible; use IAM Roles + AWS SSO.
* Rotate credentials automatically; enforce SCPs to block creation of IAM users (in AWS Organizations).

---

## 3.3 Service Controls (SCPs)

Use SCPs to prevent privilege escalation regardless of IAM role errors:

* Block `iam:*` except for specific admin roles.
* Block creation or update of IAM policies.
* Restrict Create/Update Lambda/EC2 roles.
* Deny S3 public ACLs and KMS key policy modifications.

---

## 3.4 Resource Hardening

### EC2

* Disable instance metadata v1 (enforce IMDSv2).
* Restrict the ability to attach or modify instance profiles.

### Lambda

* Block UpdateFunctionCode and UpdateFunctionConfiguration for non-admin roles.

### CloudFormation

* Restrict who can deploy or update stacks with IAM capabilities:

  ```
  CAPABILITY_IAM
  CAPABILITY_NAMED_IAM
  ```

---

# 4. Mitigation Using Prowler Output

After running Prowler:

1. Export results to JSON.
2. Filter for failing IAM or privilege-escalation checks.
3. Prioritize remediation based on severity:

   * High: wildcard permissions, assume-role misconfigurations.
   * Medium: missing MFA, inactive access keys.
   * Low: monitoring-related issues.

You can also integrate Prowler with:

* AWS Security Hub
* SIEM tools (Splunk, Elastic, QRadar, Sentinel)
* Terraform or CI pipelines

This allows automated detection and remediation workflows.

Below is a **clean, complete, defensive guide** showing **HOW TO FIX AWS privilege-escalation risks** using both:

1. **AWS Management Console (GUI)**
2. **AWS CLI**

This includes fixes for the **most common, real-world privilege-escalation paths** you will see in Prowler/IAM Access Analyzer.

This is written as an actionable security playbook for a cloud security architect.

---

# 1. FIX: Over-Permissive IAM Policies (`Action: "*"`, `Resource: "*"`)

Wildcards allow ANY action on ANY resource → direct or indirect privilege escalation.

---

## Using AWS Console (GUI)

### Step 1 – Find the Policy

1. Open **IAM Console**
2. Go to **Policies**
3. Use search to find the policy flagged by Prowler
4. Click the policy → **Permissions** tab → **JSON**

You will see something like:

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### Step 2 – Fix It

1. Click **Edit policy**
2. Replace `"*"` with explicit scoped actions:

   * Example for S3 read/write only:

   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject",
       "s3:PutObject"
     ],
     "Resource": "arn:aws:s3:::mybucket/*"
   }
   ```
3. Save the policy.
4. Confirm no other statements allow unintended actions.

---

## Using AWS CLI

### Step 1 – Get Current Policy Document

```bash
aws iam get-policy-version \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/<POLICY_NAME> \
  --version-id v1
```

### Step 2 – Create a Corrected Policy JSON File

Example: `fixed-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::mybucket/*"
  }]
}
```

### Step 3 – Apply Updated Policy Version

```bash
aws iam create-policy-version \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/<POLICY_NAME> \
  --policy-document file://fixed-policy.json \
  --set-as-default
```

---

# 2. FIX: Dangerous `iam:PassRole` with Wildcards

If a role/user can pass ANY role → possible privilege escalation.

---

## Using AWS Console (GUI)

### Step 1 – Identify Role/User

1. IAM → **Roles** or **Users**
2. Open principal flagged by Prowler.
3. Go to **Permissions** → **Inline/Attached policies**

Look for:

```json
"Action": "iam:PassRole",
"Resource": "*"
```

### Step 2 – Fix Resource Scope

1. Click **Edit policy**
2. Replace wildcard with allowed ARNs only:

Example (good):

```json
"Action": "iam:PassRole",
"Resource": [
  "arn:aws:iam::<ACCOUNT_ID>:role/EC2LimitedRole"
]
```

3. Save.

---

## Using AWS CLI

### Step 1 – Create a restricted version of the policy

`passrole-fixed.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/SpecificAllowedRole"
    }
  ]
}
```

### Step 2 – Attach it (for roles or users)

#### For a Role:

```bash
aws iam put-role-policy \
  --role-name DevRole \
  --policy-name PassRoleRestricted \
  --policy-document file://passrole-fixed.json
```

#### For a User:

```bash
aws iam put-user-policy \
  --user-name devuser \
  --policy-name PassRoleRestricted \
  --policy-document file://passrole-fixed.json
```

---

# 3. FIX: Overly Broad `sts:AssumeRole` Trust Policies

A trust policy that allows **ANY identity** (or entire accounts) to assume a privileged role creates escalation paths.

---

## Using AWS Console (GUI)

### Step 1 – Open the Role

1. IAM → **Roles**
2. Search for flagged role
3. Select → **Trust relationships**

Bad trust example:

```json
"Principal": { "AWS": "*" }
```

or:

```json
"Principal": { "AWS": "arn:aws:iam::<ANY_OTHER_ACCOUNT>:root" }
```

### Step 2 – Fix Trust Relationship

1. Click **Edit trust policy**
2. Replace with restricted ARNs:

Good example:

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/SpecificRole"
  },
  "Action": "sts:AssumeRole"
}
```

3. Save changes.

---

## Using AWS CLI

### Step 1 – Create a safe trust policy

Example: `trust-fixed.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::<ACCOUNT_ID>:role/DevOpsRole"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Step 2 – Apply the fixed trust policy

```bash
aws iam update-assume-role-policy \
  --role-name <ROLENAME> \
  --policy-document file://trust-fixed.json
```

---

# 4. FIX: IAM Users with Administrative Permissions

IAM users are riskier than roles (keys get leaked, no session boundaries).

---

## Using AWS Console (GUI)

### Step 1 – Identify Admin-Level IAM Users

1. IAM → **Users**
2. Check **Permissions** tab
3. Look for:

   * AdministratorAccess
   * PowerUserAccess
   * Inline wildcard policies

### Step 2 – Fix

1. Detach high-privilege policies
2. Replace with least-privilege role assignments
3. Enforce MFA
4. Create an SSO permission set or IAM role

---

## Using AWS CLI

### 1. List attached user policies

```bash
aws iam list-attached-user-policies --user-name alice
```

### 2. Detach AdministratorAccess

```bash
aws iam detach-user-policy \
  --user-name alice \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 3. Attach a least-privilege policy

```bash
aws iam attach-user-policy \
  --user-name alice \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/LeastPrivilegePolicy
```

---

# 5. FIX: Lambda / EC2 Privilege Escalation Vectors

(When a low-privilege user can update a function or instance profile)

---

## Using AWS Console (GUI)

### Lambda

1. Open Lambda → find risky function
2. Go to **Configuration → Permissions**
3. Check execution role for over-privileged policies
4. Go to **Access Control → Resource-based policies**
5. Ensure only trusted roles/users can update configuration or code:

   * Remove wildcard principals

### EC2

1. Open EC2 → Instance
2. Check **IAM Role**
3. Ensure instance profile role is minimal
4. Restrict who can update the instance IAM role

---

## Using AWS CLI

### Replace a high-privilege Lambda execution role

```bash
aws lambda update-function-configuration \
  --function-name MyFunction \
  --role arn:aws:iam::<ACCOUNT_ID>:role/LeastPrivilegeLambdaRole
```

### Restrict who can modify EC2 instance profiles

Use IAM policies:

```bash
aws iam put-role-policy \
  --role-name DevOpsRole \
  --policy-name EC2Restrict \
  --policy-document file://ec2-restrict.json
```

---

# 6. FIX: Remove IAM Inline Policies from Users and Roles

Inline policies make auditing and governance harder.

---

## Using AWS Console (GUI)

1. IAM → Users or Roles
2. Go to **Permissions**
3. Under **Inline policies** click:

   * **Delete** or
   * Convert to a managed policy
4. Reattach as a managed policy if needed.

---

## Using AWS CLI

### List inline user policies

```bash
aws iam list-user-policies --user-name bob
```

### Delete inline policy

```bash
aws iam delete-user-policy \
  --user-name bob \
  --policy-name InlinePolicy1
```

---

# 7. (Optional but HIGH recommendation)

# Use AWS Organizations SCPs to BLOCK Escalation at Root

Example SCP to stop admins from creating new admin roles:

```json
{
  "Effect": "Deny",
  "Action": [
    "iam:CreatePolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy"
  ],
  "Resource": "*"
}
```

Apply via AWS Organizations GUI or:

```bash
aws organizations create-policy \
  --content file://scp-deny-priv-escalation.json \
  --type SERVICE_CONTROL_POLICY \
  --name DenyPrivilegeEscalation
```

---



Tell me if you want any of these.
