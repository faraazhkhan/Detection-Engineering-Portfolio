# Registry Hive Export of SAM, SYSTEM or SECURITY via reg.exe

| | |
|---|---|
| **MITRE ATT&CK** | T1003.002 |
| **Tactic** | Credential Access |
| **Severity** | High |
| **Log source** | Windows process creation events with command-line logging |
| **Required fields** | Image, OriginalFileName, CommandLine, ParentImage, User |
| **Rule file** | [`registry-hive-save-credential-theft.yml`](./registry-hive-save-credential-theft.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects reg.exe saving the SAM, SYSTEM or SECURITY registry hives to a file, a step attackers use to extract local password hashes offline.

## Detection logic
reg.exe (matched by file name or `OriginalFileName`) with:
- `save` and a command line naming the SAM, SYSTEM or SECURITY hive. `reg save` is the standard way to dump a hive to a file, so any named path under those hives counts.
- `export` only when the command line names a whole hive (for example `reg export HKLM\SYSTEM file.reg`). `reg export` is also used for harmless troubleshooting of sub-keys such as `HKLM\SYSTEM\CurrentControlSet\Services\...`, so I scoped it to the hive itself with a regular expression to keep the noise down.

## How to test
In an isolated Windows VM, run `reg save HKLM\SAM C:\temp\sam.save` from an elevated prompt, then delete the file. Atomic Red Team has tests for T1003.002.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Backup or imaging tools that export registry hives.
- Administrators exporting registry keys for troubleshooting (note that `export` of HKLM\SYSTEM subkeys may match; review the exact key).

Allow-list backup software. Raise priority when more than one hive is saved in a short time, or when the output path is a temp or user folder.

## Limitations
Attackers can also copy the hives through volume shadow copies or use other tools that read them without reg.exe. Pair this with the shadow copy rule and with credential dumping detections.

Credential theft often skips reg.exe entirely: native API calls, copying the hives from a volume shadow copy, reading LSASS memory, or other tools (T1003 and its sub-techniques). Those need file-access, shadow-copy and credential-dumping coverage, which process command lines alone cannot provide. The `export` branch uses a regular expression, so check your SIEM supports the `re` modifier.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1003/002/
