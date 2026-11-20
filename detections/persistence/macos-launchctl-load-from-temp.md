# macOS launchctl Loading a Job from a Temporary or Shared Path

| | |
|---|---|
| **MITRE ATT&CK** | T1543.001, T1543.004 |
| **Tactic** | Persistence |
| **Severity** | Medium |
| **Log source** | macOS process execution telemetry (EDR or Endpoint Security framework feed) |
| **Required fields** | Image, CommandLine |
| **Rule file** | [`macos-launchctl-load-from-temp.yml`](./macos-launchctl-load-from-temp.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects launchctl loading or bootstrapping a launchd job whose plist sits in a temporary or world-writable location, which is unusual for legitimate software and common in macOS persistence.

## Detection logic
launchctl invoked with load or bootstrap where the command line references /tmp, /var/tmp, or /Users/Shared.

## How to test
On a macOS test machine or VM, copy a harmless plist into /tmp and run `launchctl load /tmp/test.plist`, then unload and delete it. Confirm your macOS telemetry captures the full launchctl command line first.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Installers that stage a plist in /tmp before moving it.
- Developer or IT tooling that loads test launchd jobs.

Exclude known installer parents (for example signed package installers) and review the plist contents and program path for each hit.

## Limitations
Does not cover plists loaded from normal LaunchAgents folders or persistence written directly to disk and loaded at next login. Add file-creation coverage for ~/Library/LaunchAgents and /Library/LaunchDaemons.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1543/001/
- https://attack.mitre.org/techniques/T1543/004/
