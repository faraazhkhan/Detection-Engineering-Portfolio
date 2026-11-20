# AWS CloudTrail Logging Stopped or Modified

| | |
|---|---|
| **MITRE ATT&CK** | T1562.008 |
| **Tactic** | Defense Evasion |
| **Severity** | High |
| **Log source** | AWS CloudTrail management events |
| **Required fields** | eventSource, eventName, userIdentity, sourceIPAddress |
| **Rule file** | [`aws-cloudtrail-logging-disabled.yml`](./aws-cloudtrail-logging-disabled.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects API calls that stop, delete, or alter a CloudTrail trail's configuration, which can blind detection and investigation in an AWS account.

## Detection logic
CloudTrail management events from `cloudtrail.amazonaws.com` whose eventName is one of:
- `StopLogging` and `DeleteTrail`: the high-signal actions. They turn logging off or remove the trail.
- `UpdateTrail`: changes trail settings, such as its destination bucket or whether it is multi-region.
- `PutEventSelectors` and `PutAdvancedEventSelectors`: change which events the trail records, so an attacker can quietly stop it capturing activity they care about. Trails use either the classic or the advanced selectors, so both are included.

`StopLogging` and `DeleteTrail` are the clearest tampering. The other three are also used in routine maintenance, so they are the first ones to tune.

## How to test
In a personal sandbox AWS account, run `aws cloudtrail stop-logging --name <trail-name>`, then `aws cloudtrail start-logging --name <trail-name>`. Do not run this in a shared or production account.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Planned trail changes made by infrastructure-as-code pipelines or platform engineers.
- Account setup and migration work.

Allow-list the specific IAM roles used by your deployment pipeline, and keep StopLogging and DeleteTrail alerting at high priority regardless of who made the change. If `UpdateTrail` or the selector calls are too noisy, lower their severity rather than dropping them.

### What to check on a hit
The event carries the context that separates a planned change from tampering:
- `userIdentity`: the user, role or assumed-role session that made the call, and whether it is one of your pipeline roles.
- `sourceIPAddress` and `userAgent`: whether it came from a known network or tool (for example Terraform or the console) or something unexpected.
- `awsRegion` and `recipientAccountId`: which region and account were affected.
- `requestParameters`: which trail, and for the selector calls, what was changed.
- `errorCode`: a value such as `AccessDenied` means the attempt failed. It is still worth investigating, since someone was probing, and the rule deliberately alerts on failed attempts too.

## Limitations
If the attacker disables logging in a region or account you are not collecting from, you will never see the event. Centralize trails in a dedicated log-archive account with restricted access.

Multi-region and organization coverage matters here. A multi-region trail or an AWS Organizations trail keeps logging events from other regions and member accounts even if a single-region trail in one account is stopped. Organization trails also cannot be modified or deleted from member accounts, which is a good reason to use one. Without that setup, an attacker with access to one account or region can blind only the trail you are watching.

This rule also does not see tampering with where the logs are stored, such as changing the S3 bucket policy or lifecycle rules, or turning off log file validation. Alarms on those changes, and AWS Config rules that check CloudTrail is enabled, are a useful second layer.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1562/008/
