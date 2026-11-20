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
CloudTrail management events whose eventName is StopLogging, DeleteTrail, UpdateTrail, or PutEventSelectors.

## How to test
In a personal sandbox AWS account, run `aws cloudtrail stop-logging --name <trail-name>`, then `aws cloudtrail start-logging --name <trail-name>`. Do not run this in a shared or production account.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Planned trail changes made by infrastructure-as-code pipelines or platform engineers.
- Account setup and migration work.

Allow-list the specific IAM roles used by your deployment pipeline, and keep StopLogging and DeleteTrail alerting at high priority regardless of who made the change.

## Limitations
If the attacker disables logging in a region or account you are not collecting from, you will never see the event. Centralize trails in a dedicated log-archive account with restricted access.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1562/008/
