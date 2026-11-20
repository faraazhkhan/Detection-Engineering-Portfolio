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
A command line contains Set-MpPreference with DisableRealtimeMonitoring, or Add-MpPreference with an Exclusion parameter.

## How to test
In an isolated Windows VM, run `Set-MpPreference -DisableRealtimeMonitoring $true` in an elevated PowerShell, then turn it back on. The Atomic Red Team tests for T1562.001 cover this.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- IT or security teams adding exclusions for approved software.
- Software installers that add their own Defender exclusions.

Allow-list the deployment tool or admin accounts that legitimately manage exclusions. Review who added an exclusion and for which path.

## Limitations
Tamper Protection blocks many of these changes, and attackers can use other methods, such as the registry or Group Policy, that this rule does not see.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1562/001/
