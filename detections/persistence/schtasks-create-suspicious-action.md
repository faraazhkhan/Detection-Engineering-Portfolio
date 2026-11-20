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
schtasks.exe with `/create` where the action path points to AppData, Temp, or Public, or invokes a script host or LOLBin.

## How to test
Atomic Red Team T1053.005 creates scheduled tasks with schtasks (`Invoke-AtomicTest T1053.005 -ShowDetailsBrief`). Alternatively create a task by hand that runs `powershell.exe` and confirm the alert, then delete the task.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Software installers and updaters that register tasks from AppData.
- Admin scripts that schedule PowerShell jobs.

Exclude known updater task names and signed vendor paths. Consider raising severity when the task runs as SYSTEM or the parent is an Office app or browser.

## Limitations
Misses tasks created through the Task Scheduler COM API or PowerShell cmdlets (Register-ScheduledTask). Add Security EID 4698 coverage for those.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1053/005/
