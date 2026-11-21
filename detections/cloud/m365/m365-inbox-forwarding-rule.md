# Microsoft 365 Inbox Rule or Mailbox Forwarding to External Address

| | |
|---|---|
| **MITRE ATT&CK** | T1114.003 |
| **Tactic** | Collection |
| **Severity** | High |
| **Log source** | Microsoft 365 unified audit log (Exchange admin audit) |
| **Required fields** | Operation, Parameters, UserId, ClientIP |
| **Rule file** | [`m365-inbox-forwarding-rule.yml`](./m365-inbox-forwarding-rule.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects creation of inbox rules or mailbox settings that forward or redirect mail, a common technique in business email compromise to monitor victims and hide replies.

## Detection logic
An Exchange audit event for a new or changed inbox rule that sets a forward or redirect target, or a mailbox change that sets a forwarding address.

## How to test
In a Microsoft 365 test tenant, create an inbox rule that forwards mail to a test address, then delete it. Do not use a production mailbox.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Users who forward work mail to a personal address or delegate (also a data-loss risk).
- Shared mailbox and assistant workflows.

Compare the target address to your tenant domains. External targets are the real risk, so raise priority for them, and allow-list approved forwarding.

### Internal versus external forwarding
The rule fires on any forward or redirect, so forwarding to an assistant, delegate or shared mailbox counts too. To cut the noise, compare the forwarding address's domain with your tenant's accepted domains and raise severity for external addresses. How easily you can do that depends on how your SIEM parses the `Parameters` field, which is a list of name and value pairs. A mail-flow rule or Exchange policy that blocks external auto-forwarding is the better preventive control.

### Hide and delete behavior
Attackers in business email compromise campaigns often pair the forwarding rule with actions that hide replies or alerts. Look in the same rule's parameters for `DeleteMessage`, `MarkAsRead` or `MoveToFolder` (especially to Deleted Items, RSS or Junk Email), and for other new inbox rules created around the same time. A forwarding rule that also deletes or hides mail is far more suspicious than one that only forwards.

## Limitations
The audit log does not always show the destination in a consistent field, so confirm the field layout in your tenant before relying on the rule. Hidden rules created through other clients may need extra coverage.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1114/003/
