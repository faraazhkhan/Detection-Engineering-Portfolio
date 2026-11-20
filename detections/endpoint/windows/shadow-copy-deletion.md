# Shadow Copies or Backup Catalog Deleted via vssadmin, wmic, diskshadow, wbadmin or PowerShell

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
Any one of these, each also matched by `OriginalFileName` so a renamed copy of the binary still matches:
- `vssadmin.exe` or `diskshadow.exe` with both "delete" and "shadows" in the command line (for example `vssadmin delete shadows /all /quiet`).
- `wmic.exe` with both "shadowcopy" and "delete" (for example `wmic shadowcopy delete`). Note that WMIC is deprecated and missing from newer Windows 11 builds, so this branch matters mostly on older systems.
- `wbadmin.exe` with "delete" plus `catalog`, `systemstatebackup` or `backup`. Ransomware often runs `wbadmin delete catalog -quiet` to make Windows Backup forget its backups. This is backup destruction rather than shadow copies, which is why the rule's title now covers both.
- PowerShell or pwsh with `Win32_ShadowCopy` and a delete method (`Delete`, `Remove-CimInstance` or `Remove-WmiObject`), the PowerShell route to the same result.

All command-line matches use `contains|all`, so the keywords can appear in any order and with any flags or spacing (`/quiet`, `/for=C:`, `/all`).

## How to test
In an isolated Windows VM, run `vssadmin delete shadows /all /quiet` (or the Atomic Red Team test for T1490). Never run this on a machine whose restore points you need.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Backup or disk-cleanup software that removes old shadow copies.
- Administrators freeing disk space on a server.

Allow-list known backup software and its service accounts. Keep this alert high priority anywhere else, because a surprise shadow copy deletion is a strong ransomware signal.

## Response context
Treat a hit as possible ransomware in progress until shown otherwise, because deletion usually happens just before encryption or data destruction.
1. Check the host for other signs: mass file renames, new unknown processes, recent remote logons, Defender or backup services stopped.
2. Be ready to isolate the host quickly, and check whether the same account or source reached other hosts.
3. Verify that backups are intact, especially offline or immutable copies, and that the backup catalog on other servers hasn't been touched.
4. Find the parent process and account that ran the command.

## Limitations
- `diskshadow` is often run from a script file (`diskshadow /s script.txt`), so the words "delete shadows" are inside the script and not on the command line. That case needs file content or script visibility.
- Obfuscated PowerShell (encoded commands with `-enc`, string concatenation, or backticks inside `Win32_ShadowCopy` or `Remove-CimInstance`) won't show the plain keywords on the process command line. PowerShell Script Block Logging (Event ID 4104) records the deobfuscated script, so a companion rule on 4104 closes that gap.
- Direct API calls from a compiled tool, or shadow copy storage being resized so old copies are discarded (for example through `vssadmin resize shadowstorage`), won't match these command lines.
- Not detecting is not the same as not happening. Pair this with backup-job failure alerts and monitoring of VSS service and storage events.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1490/
