# PsExec Service Installed on Host

| | |
|---|---|
| **MITRE ATT&CK** | T1021.002, T1569.002 |
| **Tactic** | Lateral Movement |
| **Severity** | Medium |
| **Log source** | Windows System log, Service Control Manager event 7045 |
| **Required fields** | Provider_Name, EventID, ImagePath |
| **Rule file** | [`psexec-service-installed.yml`](./psexec-service-installed.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects installation of the PSEXESVC service, which appears on a remote host when PsExec is used to execute commands, often during lateral movement.

## Detection logic
Service Control Manager event 7045 where the installed service's image path contains PSEXESVC.

## How to test
In a two-VM lab, run PsExec from one host against the other (for example `psexec \\target cmd`), then check the System log on the target for event 7045. Atomic Red Team T1569.002 also covers PsExec-style execution.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Administrators and IT teams that use PsExec for remote management.

Baseline which admin workstations and accounts legitimately use PsExec, and raise severity when it originates from non-admin hosts or runs shortly after a new logon.

## Limitations
Renamed PsExec binaries or custom service names will bypass the string match. Consider adding a rule for new services running from ADMIN$ or unusual paths, and correlate with network logon events.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1021/002/
- https://attack.mitre.org/techniques/T1569/002/
