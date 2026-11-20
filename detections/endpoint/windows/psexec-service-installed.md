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
System log event 7045 ("A service was installed in the system", written by the Service Control Manager) where either the service name is `PSEXESVC` or the image path contains `PSEXESVC`.

### Design choices
- The rule matches on `EventID: 7045` and the service fields only. I removed an explicit `Provider_Name: 'Service Control Manager'` check. Event 7045 comes from that provider anyway, and some SIEMs normalize or drop the provider field, which would stop the rule translating or matching. Fewer field dependencies makes it more portable.
- Checking both `ServiceName` and `ImagePath` covers backends that only parse one of them.

## How to test
In a two-VM lab, run PsExec from one host against the other (for example `psexec \\target cmd`), then check the System log on the target for event 7045. Atomic Red Team T1569.002 also covers PsExec-style execution.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Administrators and IT teams that use PsExec for remote management.

Baseline which admin workstations and accounts legitimately use PsExec, and raise severity when it originates from non-admin hosts or runs shortly after a new logon.

## Limitations
The rule keys on the string `PSEXESVC`. A PsExec fork, a custom wrapper, or a build that renames both the service and the binary will not match. Related tools (for example PAExec, RemCom, or Impacket-style execution) use their own service names. A broader companion rule on new services whose image path is in ADMIN$, a user-writable folder, or an unusual location would cover those.

### Who did it, and from where
Event 7045 shows that a service was installed on the target, but not who pushed it or from which host. To confirm remote lateral movement versus someone installing a service locally, pivot on:
- Security Event 4624 with Logon Type 3 (network logon) on the target just before the 7045, to get the account and the source IP or workstation.
- Admin share access to `ADMIN$` (Security Events 5140 and 5145, if file share auditing is enabled), since PsExec copies its service binary there.
- Process creation for `PSEXESVC.exe` and its child processes (Sysmon Event 1 or Security 4688), which shows what was actually run.
- Named pipe activity for the `psexesvc` pipe (Sysmon Events 17 and 18, if configured).

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1021/002/
- https://attack.mitre.org/techniques/T1569/002/
