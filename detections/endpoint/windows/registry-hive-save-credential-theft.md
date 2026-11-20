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
reg.exe with `save` or `export` and a command line that names the SAM, SYSTEM or SECURITY hive.

## How to test
In an isolated Windows VM, run `reg save HKLM\SAM C:\temp\sam.save` from an elevated prompt, then delete the file. Atomic Red Team has tests for T1003.002.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Backup or imaging tools that export registry hives.
- Administrators exporting registry keys for troubleshooting (note that `export` of HKLM\SYSTEM subkeys may match; review the exact key).

Allow-list backup software. Raise priority when more than one hive is saved in a short time, or when the output path is a temp or user folder.

## Limitations
Attackers can also copy the hives through volume shadow copies or use other tools that read them without reg.exe. Pair this with the shadow copy rule and with credential dumping detections.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1003/002/
