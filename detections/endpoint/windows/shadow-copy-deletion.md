# Volume Shadow Copies Deleted via vssadmin or wmic

| | |
|---|---|
| **MITRE ATT&CK** | T1490 |
| **Tactic** | Impact |
| **Severity** | High |
| **Log source** | Windows process creation events (Sysmon Event ID 1 or Security Event ID 4688 with command-line logging) |
| **Required fields** | Image, CommandLine, ParentImage, User |
| **Rule file** | [`shadow-copy-deletion.yml`](./shadow-copy-deletion.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects commands that delete Windows volume shadow copies, which ransomware operators run to stop victims from restoring files from backups.

## Detection logic
A process is vssadmin.exe with both "delete" and "shadows" in the command line, or wmic.exe with both "shadowcopy" and "delete".

## How to test
In an isolated Windows VM, run `vssadmin delete shadows /all /quiet` (or the Atomic Red Team test for T1490). Never run this on a machine whose restore points you need.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Backup or disk-cleanup software that removes old shadow copies.
- Administrators freeing disk space on a server.

Allow-list known backup software and its service accounts. Keep this alert high priority anywhere else, because a surprise shadow copy deletion is a strong ransomware signal.

## Limitations
Attackers can delete shadow copies through other methods, such as direct API calls or PowerShell WMI calls, that avoid these command lines.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1490/
