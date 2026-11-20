# Web Proxy Request from a Command-Line Scripting Tool

| | |
|---|---|
| **MITRE ATT&CK** | T1071.001 |
| **Tactic** | Command and Control |
| **Severity** | Low |
| **Log source** | Web proxy or secure web gateway logs |
| **Required fields** | c-useragent, cs-host, c-ip, c-uri, user |
| **Rule file** | [`proxy-scripting-tool-user-agent.yml`](./proxy-scripting-tool-user-agent.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects web requests whose user agent identifies a command-line tool (curl, wget, python-requests or PowerShell), which is how many scripts and malware talk to the internet but rarely how a normal user browses.

## Detection logic
The request user agent starts with curl/, Wget/ or python-requests/, or contains WindowsPowerShell.

## How to test
From a test machine behind your proxy, run `curl http://example.com` and a PowerShell `Invoke-WebRequest`, then check the proxy log for the user agent strings.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Build servers, developer machines, monitoring tools, and legitimate scripts that call web services.
- Software update and package-manager tools.

This rule is noisy by design and works best as a hunting lead or for ordinary user workstations only. Exclude server and developer subnets, then raise priority for requests to rare or newly seen destinations.

## Limitations
Attackers can set any user agent they like, so a miss proves nothing. Treat this as a low-severity lead to combine with other signals, not as a standalone alert.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1071/001/
