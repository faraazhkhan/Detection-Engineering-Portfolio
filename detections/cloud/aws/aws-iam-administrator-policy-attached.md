# AWS AdministratorAccess Policy Attached to User, Role or Group

| | |
|---|---|
| **MITRE ATT&CK** | T1098.003 |
| **Tactic** | Privilege Escalation |
| **Severity** | High |
| **Log source** | AWS CloudTrail management events (IAM) |
| **Required fields** | eventSource, eventName, requestParameters.policyArn, userIdentity, sourceIPAddress |
| **Rule file** | [`aws-iam-administrator-policy-attached.yml`](./aws-iam-administrator-policy-attached.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects the AWS-managed AdministratorAccess policy being attached to an IAM user, role or group, a direct path to full control of an AWS account.

## Detection logic
An IAM Attach*Policy call where the policy ARN is the AWS-managed AdministratorAccess policy.

## How to test
In a personal sandbox AWS account, attach AdministratorAccess to a throwaway test user (`aws iam attach-user-policy`), then detach it. Do not use a shared or production account.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Planned onboarding of new administrators through an approved process.
- Infrastructure-as-code pipelines that create admin roles.

Allow-list the roles your deployment pipeline uses and the people approved to grant admin. Alert on everything else.

## Limitations
Attackers can gain admin through inline policies or custom policies with broad permissions. Add rules for CreatePolicyVersion and PutUserPolicy for wider coverage.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1098/003/
