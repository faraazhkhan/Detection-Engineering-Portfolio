# AWS Root Account Activity

| | |
|---|---|
| **MITRE ATT&CK** | T1078.004 |
| **Tactic** | Initial Access / Persistence |
| **Severity** | High |
| **Log source** | AWS CloudTrail management events |
| **Required fields** | userIdentity.type, eventName, sourceIPAddress, userAgent, eventSource, eventType |
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

### What to check on a hit
- `sourceIPAddress` and `userAgent`: an interactive console login, the CLI, or an SDK from an unfamiliar network.
- `userIdentity.invokedBy`: shows when AWS itself or another service acted on the root account's behalf, which helps separate a person from automation.
- `eventName`: a root console login (`ConsoleLogin`) is different from root creating access keys or changing MFA, and the second is much more worrying.
- Whether the root account has MFA on and no access keys. Neither should be needed for daily work.

## Limitations
CloudTrail must be enabled in all regions and delivered to a protected account, or root activity in a missed region goes unseen.

Field names depend on your SIEM. `userIdentity.type` and `eventType` are nested in raw CloudTrail JSON, and some pipelines flatten them with a different separator. Map them to your product before relying on the rule. The `AwsServiceEvent` exclusion removes events AWS generates itself under the account, which is normally what you want, but check that your SIEM exposes `eventType` before relying on it.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1078/004/
