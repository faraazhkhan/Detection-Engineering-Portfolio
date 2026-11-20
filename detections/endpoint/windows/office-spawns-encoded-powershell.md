# Office Application Spawning Encoded PowerShell

| | |
|---|---|
| **MITRE ATT&CK** | T1059.001, T1204.002 |
| **Tactic** | Execution |
| **Severity** | High |
| **Log source** | Windows process creation (Sysmon EID 1 or Security EID 4688 with command-line auditing) |
| **Required fields** | ParentImage, Image, OriginalFileName, CommandLine |
| **Rule file** | [`office-spawns-encoded-powershell.yml`](./office-spawns-encoded-powershell.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects a Microsoft Office application launching PowerShell with an encoded command, a common pattern after a malicious document is opened.

## Detection logic
Office parent process (Word, Excel, PowerPoint, Outlook) with a PowerShell child whose command line uses an encoded-command flag.

## How to test
In an isolated VM, open a test document whose macro runs `powershell -enc <base64 of a harmless command>`, or run the Atomic Red Team test for T1059.001 that uses encoded commands (see `Invoke-AtomicTest T1059.001 -ShowDetailsBrief`).

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Legacy macros or add-ins in some enterprise workflows that call encoded PowerShell.

Baseline which macros or add-ins legitimately spawn PowerShell, then exclude by exact command line or signed script path.

## Limitations
Attackers can avoid the encoded flag or use other parents (wscript, mshta). The flag list can also be bypassed by flag abbreviations not listed here.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1204/002/
