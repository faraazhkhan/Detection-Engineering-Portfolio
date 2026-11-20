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
Detects rundll32 loading comsvcs.dll and calling its MiniDump export, by name or by ordinal 24, a living-off-the-land technique commonly used to dump LSASS memory and harvest credentials.

## Detection logic
rundll32.exe (or a renamed copy, caught via OriginalFileName) whose command line contains `comsvcs` and calls the dump function either by name (`MiniDump`) or by export ordinal (`#24` or `#+24`). The ordinal forms matter because `MiniDump` is export number 24 in comsvcs.dll, so `rundll32 comsvcs.dll,#24 <PID> dump.dmp full` does the same thing without the word MiniDump.

### Why the rule does not check for lsass.exe
The command line normally carries the target's numeric process ID (for example `684`), not the name `lsass.exe`, so the rule cannot confirm the target is LSASS from the command line alone. That is acceptable: there is almost no legitimate reason to dump a process through rundll32 and comsvcs.dll, so alerting on any use is the right design. During triage, check which process the PID belongs to (Sysmon EID 10 or process list) to confirm whether it was LSASS.

## How to test
Atomic Red Team T1003.001 includes a comsvcs.dll MiniDump test. List tests with `Invoke-AtomicTest T1003.001 -ShowDetailsBrief`. Run it only in an isolated lab VM.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare. Administrators or support tools creating process dumps for troubleshooting.

Allow-list known admin hosts or the specific parent process of approved dump tooling. Anything touching LSASS should still be reviewed.

## Limitations
Does not catch other dump methods (Task Manager, procdump, direct API calls). The `#24` match is a plain substring, so it can also match longer ordinals that start with 24 (for example `#240`); this is unlikely in practice but worth knowing. Attackers can also obfuscate the command line or call the export through other loaders. Pair with LSASS process-access detection (Sysmon EID 10).

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1003/001/
