# Windows Event Log Cleared via wevtutil or PowerShell

| | |
|---|---|
| **MITRE ATT&CK** | T1070.001 |
| **Tactic** | Defense Evasion |
| **Severity** | High |
| **Log source** | Windows process creation (Sysmon EID 1 or Security EID 4688 with command-line auditing) |
| **Required fields** | Image, CommandLine |
| **Rule file** | [`windows-event-log-cleared.yml`](./windows-event-log-cleared.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects attempts to clear Windows event logs using wevtutil or the Clear-EventLog cmdlet, a common anti-forensics step.

## Detection logic
wevtutil.exe with the `cl` or `clear-log` subcommand, or a command line containing Clear-EventLog.

## How to test
Atomic Red Team T1070.001 includes a wevtutil log-clearing test (`Invoke-AtomicTest T1070.001 -ShowDetailsBrief`). Run it on a disposable VM only, since it deletes logs.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- System administrators clearing logs during maintenance or after imaging.
- Build or lab environments that reset logs automatically.

Exclude known maintenance accounts or hosts, but keep alerting on clears of Security and Sysmon logs. Pair with Security EID 1102 and System EID 104 as a second signal.

## Limitations
Process-based only. Log clearing through direct API calls or other tooling will not match, so also alert on Security EID 1102 and System EID 104.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1070/001/
