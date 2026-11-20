# Windows Event Log Cleared (Security EID 1102 or System EID 104)

| | |
|---|---|
| **MITRE ATT&CK** | T1070.001 |
| **Tactic** | Defense Evasion |
| **Severity** | High |
| **Log source** | Windows Security and System event logs (forwarded to your SIEM or EDR) |
| **Required fields** | Channel, EventID, Provider_Name |
| **Rule file** | [`windows-audit-log-cleared-event.yml`](./windows-audit-log-cleared-event.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects the events Windows writes when an event log is cleared. This is the outcome-based companion to [`windows-event-log-cleared`](./windows-event-log-cleared.md), which only sees the command used to clear a log.

## Detection logic
Either of:
- Security Event ID **1102**: "The audit log was cleared." It is written to the Security log itself when that log is cleared.
- System Event ID **104** from the `Microsoft-Windows-Eventlog` provider: "The log file was cleared." It is written to the System log when another log (Application, Sysmon, PowerShell, and so on) is cleared.

Neither event depends on which tool cleared the log. wevtutil, PowerShell, a custom binary, or a GUI action all produce the same event.

## Why pair it with the process rule
- The process rule gives early warning and context (the parent process, the command line), but it only matches when specific strings appear.
- This rule confirms the log was actually cleared, whatever the method. Together, the process rule explains how and this one proves it happened.

## How to test
On a disposable VM, clear the Application log (`wevtutil cl Application`) and check for System EID 104. Clear the Security log in the same way and check for Security EID 1102. Clearing logs deletes data, so use a throwaway machine only.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Administrators clearing logs during maintenance or after imaging.
- Build or lab systems that reset logs on a schedule.

Keep alerting on a Security log clear even from admins, because it is rarely routine. Exclude known maintenance hosts or accounts only for System 104 events on noisy logs. The event includes the account that cleared the log (SubjectUserName in 1102), which is the first thing to review.

## Limitations
- If the attacker stops the Event Log service or tampers with the logs another way (for example, deleting `.evtx` files from disk after stopping the service), these events may not be written.
- If the host is not forwarding logs in near real time, an attacker who clears the local log may remove the evidence before it reaches your SIEM. The clear event itself is usually forwarded first, which is why this rule is useful, but only if forwarding is working.
- Requires the Security log to be collected. EID 1102 is written by default; no extra audit policy is needed.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1070/001/
