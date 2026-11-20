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
Office parent process (Word, Excel, PowerPoint, Outlook, Access, Publisher, Visio, OneNote) with a PowerShell child whose command line uses an encoded-command flag.

### Why the flag list looks like this
PowerShell accepts any unambiguous prefix of `-EncodedCommand`, so `-e`, `-en`, `-enc` and `-encodedcommand` all work, and `-ec` is a documented alias. It also accepts `/` in place of `-`. The rule matches ` -e `, ` -en` (which also covers every longer form), ` -ec ` and the same three with `/`. Starting at `-en` avoids colliding with unrelated flags such as `-ExecutionPolicy` (`-ex`).

## How to test
In an isolated VM, open a test document whose macro runs `powershell -enc <base64 of a harmless command>`, or run the Atomic Red Team test for T1059.001 that uses encoded commands (see `Invoke-AtomicTest T1059.001 -ShowDetailsBrief`).

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Legacy macros or add-ins in some enterprise workflows that call encoded PowerShell.

Baseline which macros or add-ins legitimately spawn PowerShell, then exclude by exact command line or signed script path.

## Limitations
The rule only sees PowerShell started directly by an Office process. Macros can decouple the parent: they may use WMI (so `wmiprvse.exe` becomes the parent) or COM objects that launch the process through `explorer.exe` or `svchost.exe`, which breaks the direct Office-to-PowerShell chain. They can also go through an intermediate such as `cmd.exe`, or use other parents (wscript, mshta), or avoid the encoded flag altogether. Pair this rule with detections for WMI process creation and for script hosts launched from Office documents. The ` -en` match is a plain substring, so it can also match `-Encoding` inside script text (for example `Out-File -Encoding utf8`); the Office-parent requirement keeps this rare.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1204/002/
