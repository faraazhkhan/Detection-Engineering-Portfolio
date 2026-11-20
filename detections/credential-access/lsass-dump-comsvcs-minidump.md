# LSASS Memory Dump via comsvcs.dll MiniDump

| | |
|---|---|
| **MITRE ATT&CK** | T1003.001 |
| **Tactic** | Credential Access |
| **Severity** | High |
| **Log source** | Windows process creation (Sysmon EID 1 or Security EID 4688 with command-line auditing) |
| **Required fields** | Image, OriginalFileName, CommandLine |
| **Rule file** | [`lsass-dump-comsvcs-minidump.yml`](./lsass-dump-comsvcs-minidump.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects rundll32 loading comsvcs.dll and calling MiniDump, a living-off-the-land technique for dumping LSASS memory to harvest credentials.

## Detection logic
rundll32.exe (or a renamed copy, caught via OriginalFileName) whose command line contains both `comsvcs` and `MiniDump`.

## How to test
Atomic Red Team T1003.001 includes a comsvcs.dll MiniDump test. List tests with `Invoke-AtomicTest T1003.001 -ShowDetailsBrief`. Run it only in an isolated lab VM.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare. Administrators or support tools creating process dumps for troubleshooting.

Allow-list known admin hosts or the specific parent process of approved dump tooling. Anything touching LSASS should still be reviewed.

## Limitations
Does not catch other dump methods (Task Manager, procdump, direct API calls). Pair with LSASS process-access detection (Sysmon EID 10).

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1003/001/
