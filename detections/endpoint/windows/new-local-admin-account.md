# Local User Created or Added to Administrators Group via net.exe

| | |
|---|---|
| **MITRE ATT&CK** | T1136.001, T1098 |
| **Tactic** | Persistence |
| **Severity** | Medium |
| **Log source** | Windows process creation events with command-line logging |
| **Required fields** | Image, CommandLine, ParentImage, User |
| **Rule file** | [`new-local-admin-account.yml`](./new-local-admin-account.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects net.exe commands that create a local account or add one to the local Administrators group, a simple way for attackers to keep access to a host.

## Detection logic
net.exe or net1.exe runs with "localgroup administrators /add" (adding to the admin group) or "user /add" (creating a local account).

## How to test
In an isolated Windows VM, run `net user testuser Passw0rd! /add` then `net localgroup administrators testuser /add`, and delete the account afterwards. Atomic Red Team has tests for T1136.001.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Help desk or imaging scripts that create local accounts.
- Software installers that create service accounts.

Allow-list your imaging and provisioning tools. Treat any hit on a server, or from an unusual parent process such as a web server, as higher priority.

## Limitations
Accounts created through PowerShell (New-LocalUser) or the Windows API will not match. Pair this rule with Windows event 4720 and 4732 where available.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1136/001/
