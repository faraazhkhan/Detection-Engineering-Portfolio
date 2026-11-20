# AWS Root Account Activity

| | |
|---|---|
| **MITRE ATT&CK** | T1078.004 |
| **Tactic** | Initial Access / Persistence |
| **Severity** | High |
| **Log source** | AWS CloudTrail management events |
| **Required fields** | userIdentity.type, eventName, sourceIPAddress, userAgent, eventSource |
| **Rule file** | [`aws-root-account-usage.yml`](./aws-root-account-usage.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects any API call or console action made with the AWS root account, which should almost never be used in day-to-day operations.

## Detection logic
CloudTrail events where the identity type is Root, excluding events AWS generates itself.

## How to test
In a personal sandbox AWS account, sign in as the root user (with MFA) and view any console page or run a read-only call, then check CloudTrail for the event. Do not use a shared or production account.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare, planned tasks that only the root user can perform, such as changing account settings or closing the account.
- Initial account setup.

Keep the allow-list small. Document any approved root tasks, require MFA on root, and alert at high priority for every other use.

## Limitations
CloudTrail must be enabled in all regions and delivered to a protected account, or root activity in a missed region goes unseen.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1078/004/
