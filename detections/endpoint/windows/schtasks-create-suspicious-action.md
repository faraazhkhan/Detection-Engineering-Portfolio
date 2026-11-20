# Scheduled Task Created with User-Writable Path or Script Host

| | |
|---|---|
| **MITRE ATT&CK** | T1053.005 |
| **Tactic** | Persistence |
| **Severity** | Medium |
| **Log source** | Windows process creation (Sysmon EID 1 or Security EID 4688 with command-line auditing) |
| **Required fields** | Image, CommandLine |
| **Rule file** | [`schtasks-create-suspicious-action.yml`](./schtasks-create-suspicious-action.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects schtasks.exe creating a task that runs from a user-writable directory or launches a script host or LOLBin, a common persistence method.

## Detection logic
schtasks.exe (or a renamed copy, caught via OriginalFileName) with `/create` or `-create` (schtasks accepts both), where the command line points to a user-writable path (AppData, Temp, Public, ProgramData, Downloads, or the unexpanded `%TEMP%`, `%APPDATA%`, `%PUBLIC%` variables) or names a script host or LOLBin (PowerShell, pwsh, mshta, wscript, cscript, regsvr32, rundll32, certutil, bitsadmin).

### Design choices
- `cmd /c` is deliberately not in the LOLBin list. It is extremely common in legitimate task actions, so it would make the rule noisy. A `cmd` task that runs from a user-writable path is still caught by the path match.
- Sigma cannot limit a match to the task action (`/tr`) argument, so a task *name* containing a word like `PowerShell` can match. This is a known trade-off for a medium-severity rule.
- Environment variables are matched literally because `schtasks.exe` can receive them unexpanded (for example when the command comes from a script or is quoted). Matching both the expanded and literal forms gives better coverage.

## How to test
Atomic Red Team T1053.005 creates scheduled tasks with schtasks (`Invoke-AtomicTest T1053.005 -ShowDetailsBrief`). Alternatively create a task by hand that runs `powershell.exe` and confirm the alert, then delete the task.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Software installers and updaters that register tasks from AppData.
- Admin scripts that schedule PowerShell jobs.

`\ProgramData\` is included because attackers stage payloads there, but many legitimate programs use it too, so expect more noise from that path. Exclude known updater task names and signed vendor paths. Consider raising severity when the task runs as SYSTEM or the parent is an Office app or browser.

## Limitations
Misses tasks created through the Task Scheduler COM API (`Schedule.Service`) or PowerShell's `Register-ScheduledTask`, because those never start `schtasks.exe`. That is a telemetry boundary: process creation will not show them. Cover them with Security Event 4698 (A scheduled task was created, which needs the "Other Object Access Events" audit policy enabled) or the Microsoft-Windows-TaskScheduler/Operational log, Event 106 (task registered).

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1053/005/
