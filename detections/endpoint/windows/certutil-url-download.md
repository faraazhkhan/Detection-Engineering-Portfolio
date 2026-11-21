# Certutil Used to Download a File from a URL

| | |
|---|---|
| **MITRE ATT&CK** | T1105 |
| **Tactic** | Command and Control |
| **Severity** | Medium |
| **Log source** | Windows process creation events with command-line logging |
| **Required fields** | Image, OriginalFileName, CommandLine, ParentImage, User |
| **Rule file** | [`certutil-url-download.yml`](./certutil-url-download.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects certutil.exe being used to fetch a file from a web address, a living-off-the-land way to download payloads using a trusted Windows tool.

## Detection logic
certutil.exe (or a renamed copy, caught by `OriginalFileName`) with one of:
- `urlcache` and an `http` address (the classic `certutil -urlcache -split -f http://...`; `http` also matches `https`).
- `verifyctl` and an `http` address, a less well-known way to make certutil fetch a file.
- `urlcache` and an `ftp://` address.

## How to test
In an isolated Windows VM, run `certutil -urlcache -f http://127.0.0.1/test.txt out.txt` against a local web server. Atomic Red Team has certutil download tests under T1105.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare. Administrators testing certificate revocation URLs or fetching a certificate or CRL.

Few legitimate uses exist. Allow-list known certificate tooling if it fires, and check what file was written and where.

## Limitations
- Command-line obfuscation can defeat literal matching: quotes or carets inserted inside the option name, extra spacing, or environment-variable expansion.
- This rule sees the download attempt only. Whatever happens to the file afterwards (it is saved, run, or loaded) needs file-creation, process and network events correlated with it.
- Other tools do the same job (bitsadmin, curl, PowerShell) and need their own coverage.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1105/
