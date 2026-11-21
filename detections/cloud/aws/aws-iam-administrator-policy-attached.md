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
An IAM `AttachUserPolicy`, `AttachRolePolicy` or `AttachGroupPolicy` call where the policy ARN ends with `:iam::aws:policy/AdministratorAccess`. The match is on the end of the ARN, not the whole string, so it also works in AWS GovCloud and China regions, where the ARN begins `arn:aws-us-gov:` or `arn:aws-cn:` instead of `arn:aws:`.

## How to test
In a personal sandbox AWS account, attach AdministratorAccess to a throwaway test user (`aws iam attach-user-policy`), then detach it. Do not use a shared or production account.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Planned onboarding of new administrators through an approved process.
- Infrastructure-as-code pipelines that create admin roles.

Allow-list the roles your deployment pipeline uses and the people approved to grant admin. Alert on everything else.

## Limitations
Attackers can gain admin through inline policies or custom policies with broad permissions. Add rules for CreatePolicyVersion and PutUserPolicy for wider coverage.

This rule covers one escalation path: attaching the managed AdministratorAccess policy. An attacker with IAM permissions has others, and none of them are covered here:
- Inline policies: `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy` with a wildcard action and resource.
- Custom policies: `CreatePolicy`, `CreatePolicyVersion` and `SetDefaultPolicyVersion` with a wildcard policy.
- Trust changes: `UpdateAssumeRolePolicy` to let an attacker-controlled principal assume a powerful role.
- Group changes: `AddUserToGroup` for a group that already has admin rights.
- Other powerful managed policies, such as `IAMFullAccess`, that allow further escalation.
I left them out of this rule on purpose. Inline policy calls happen in normal work, so matching them without inspecting the policy document would be noisy. Inspecting the document for `"Action": "*"` and `"Resource": "*"` depends on how your pipeline stores the nested policy text, so it is best done as a separate, tuned rule.

### What to check on a hit
`userIdentity` (who attached it), `requestParameters` (which user, role or group received it), `sourceIPAddress`, and `errorCode`. An `AccessDenied` means the attempt failed, which is still worth investigating. The `requestParameters.policyArn` field is nested in raw CloudTrail but may be flattened in your SIEM, so check how your product names it.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1098/003/
