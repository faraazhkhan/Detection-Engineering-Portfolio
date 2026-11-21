# Local User Created or Added to Administrators Group via net.exe

| | |
|---|---|
| **MITRE ATT&CK** | T1136.001, T1098 |
| **Tactic** | Persistence |
| **Severity** | Medium |
| **Log source** | Windows process creation events with command-line logging |
| **Required fields** | Image, CommandLine, ParentImage, User, OriginalFileName |
| **Rule file** | [`new-local-admin-account.yml`](./new-local-admin-account.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects net.exe commands that create a local account or add one to the local Administrators group, a simple way for attackers to keep access to a host.

## Detection logic
net.exe or net1.exe (matched by file name or `OriginalFileName`, so a renamed copy still matches) with either:
- `localgroup` and `/add` plus the name of the local Administrators group, which adds an account to the admin group. The group name is matched in English and in the common German, French and Spanish forms, because the built-in group is named differently on non-English Windows.
- `user` with `/add`, which creates a local account. The match is ` user ` with spaces around it on purpose: a looser `user` would also match `net localgroup Users ... /add`, which adds someone to the ordinary Users group and is not interesting.

## How to test
In an isolated Windows VM, run `net user testuser Passw0rd! /add` then `net localgroup administrators testuser /add`, and delete the account afterwards. Atomic Red Team has tests for T1136.001.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Help desk or imaging scripts that create local accounts.
- Software installers that create service accounts.

Allow-list your imaging and provisioning tools. Treat any hit on a server, or from an unusual parent process such as a web server, as higher priority.

## Limitations
Accounts created through PowerShell (New-LocalUser) or the Windows API will not match. Pair this rule with Windows event 4720 and 4732 where available.

- **Group name by language.** Process creation only gives the text that was typed, so the rule relies on the group's name. I cover English, German, French and Spanish. Other languages are not matched. The group's SID (`S-1-5-32-544`) is the same everywhere, which is why Security Event 4732 (a member was added to a security-enabled local group) is the language-independent backstop.
- **No `net.exe` at all.** Accounts and group members can be created through Windows APIs (`NetUserAdd`, `NetLocalGroupAddMembers`), PowerShell (`New-LocalUser`, `Add-LocalGroupMember`) or WMI, none of which start `net.exe`. Security Event 4720 (a user account was created) and 4732 cover those. A companion rule on 4720 and 4732 is a good addition, as with the log-cleared rule.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1136/001/
- https://attack.mitre.org/techniques/T1098/
