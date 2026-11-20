# Microsoft Defender Real-Time Protection Disabled or Exclusions Added via PowerShell

| | |
|---|---|
| **MITRE ATT&CK** | T1562.001 |
| **Tactic** | Defense Evasion |
| **Severity** | High |
| **Log source** | Windows process creation events with command-line logging |
| **Required fields** | Image, CommandLine, ParentImage, User |
| **Rule file** | [`defender-tampering.yml`](./defender-tampering.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects PowerShell commands that turn off Microsoft Defender real-time monitoring or add scan exclusions, a common step before running malware.

## Detection logic
The process must be PowerShell (`powershell.exe`, `pwsh.exe` or the ISE, matched by file name or `OriginalFileName`) and the command line must show one of:
- `Set-MpPreference` with a parameter that turns off a protection: `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection` (scanning of downloads and attachments), `DisableScriptScanning`, `DisableIntrusionPreventionSystem` or `DisableBlockAtFirstSeen`.
- `Add-MpPreference` or `Set-MpPreference` with an `Exclusion` parameter (`ExclusionPath`, `ExclusionProcess`, `ExclusionExtension`). Both cmdlets can set exclusions.

### Design choices
- Requiring a PowerShell process means a text editor, a log viewer or an unrelated tool that happens to have these words in its command line won't fire the rule.
- The rule can't tell `-DisableRealtimeMonitoring $true` (turning protection off) from `$false` (turning it back on), so a re-enable also matches. That is usually still worth a look, and it is a known noise source during testing.

## How to test
In an isolated Windows VM, run `Set-MpPreference -DisableRealtimeMonitoring $true` in an elevated PowerShell, then turn it back on. The Atomic Red Team tests for T1562.001 cover this.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- IT or security teams adding exclusions for approved software.
- Software installers that add their own Defender exclusions.

Allow-list the deployment tool or admin accounts that legitimately manage exclusions. Review who added an exclusion and for which path.

## Limitations
- Tamper Protection blocks many of these changes, so a hit may be an attempt that failed. Check the Defender log to see whether it worked.
- Attackers can use other methods this rule does not see: registry edits under `HKLM\SOFTWARE\Microsoft\Windows Defender` or its policy keys, Group Policy, WMI or COM calls, or tools like `sc` and `net stop` against Defender services. A companion rule on registry changes to those keys covers part of this.
- Obfuscation hides the keywords from the process command line: encoded commands (`-enc`), string concatenation, or backticks. PowerShell Script Block Logging (Event 4104) records the decoded script.
- The Defender log itself is a good backstop: Microsoft-Windows-Windows Defender/Operational Event 5001 (real-time protection disabled) and 5007 (configuration changed) fire whichever method was used.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1562/001/
