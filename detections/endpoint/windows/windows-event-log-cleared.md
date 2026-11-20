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
Two branches:
1. `wevtutil.exe` (or a renamed copy, caught via OriginalFileName) with a verb starting ` cl`. That covers both `cl` and `clear-log`, and `/cl` or `-cl` forms are included defensively. No other wevtutil verb starts with `cl`, so the short match is safe.
2. A PowerShell process (`powershell.exe` or `pwsh.exe`) whose command line contains `Clear-EventLog` or the .NET `ClearLog(` method (for example `[...EventLogSession]::GlobalSession.ClearLog(...)` or `$_.ClearLog()` on a log object).

### Design choices
- The PowerShell branch requires a PowerShell process, so a file path or unrelated tool that merely contains the string `Clear-EventLog` doesn't fire it.
- `Clear-EventLog` only exists in Windows PowerShell 5.1, not PowerShell 7. The .NET `ClearLog(` match covers PowerShell 7 and `Get-WinEvent` based clearing.
- A script that shells out to `wevtutil` is caught by the first branch when wevtutil starts.

## How to test
Atomic Red Team T1070.001 includes a wevtutil log-clearing test (`Invoke-AtomicTest T1070.001 -ShowDetailsBrief`). Run it on a disposable VM only, since it deletes logs.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- System administrators clearing logs during maintenance or after imaging.
- Build or lab environments that reset logs automatically.

Exclude known maintenance accounts or hosts, but keep alerting on clears of Security and Sysmon logs. Pair with Security EID 1102 and System EID 104 as a second signal.

## Limitations
Process-based only. It sees the command that tries to clear logs, not proof that logs were cleared. Clearing through direct API calls from a compiled tool, or any method that never puts these strings on a command line, will not match. The reliable backstop is the log-cleared events themselves: Security EID 1102 (the Security log was cleared) and System EID 104 (another log was cleared). Treat the pairing as two signals: the process rule gives early warning and the context (who, from where), and 1102/104 confirm the wipe actually happened. The companion rule [`windows-audit-log-cleared-event`](./windows-audit-log-cleared-event.md) alerts on EID 1102 and 104 directly and fires regardless of the tool used.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1070/001/
