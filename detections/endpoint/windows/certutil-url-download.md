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
certutil.exe (or a renamed copy, caught by OriginalFileName) with `urlcache` and an `http` address in the command line.

## How to test
In an isolated Windows VM, run `certutil -urlcache -f http://127.0.0.1/test.txt out.txt` against a local web server. Atomic Red Team has certutil download tests under T1105.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Rare. Administrators testing certificate revocation URLs or fetching a certificate or CRL.

Few legitimate uses exist. Allow-list known certificate tooling if it fires, and check what file was written and where.

## Limitations
Newer certutil options (such as `-verifyctl`) can also download files and are not covered here. Other tools (bitsadmin, curl) do the same job and need their own rules.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1105/
