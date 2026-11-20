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
launchctl invoked with `load` (legacy) or `bootstrap` (modern) where the command line references a temporary or shared staging path: /tmp, /private/tmp, /var/tmp, /private/var/tmp, /var/folders (per-user temp), /Users/Shared, or Downloads.

### Design choices
- The action match is ` load` and ` bootstrap` without a trailing space, so a tab or odd spacing after the verb still matches. The path match keeps it specific.
- Only `load` and `bootstrap` are matched. Other subcommands like `enable` or `kickstart` take a service name, not a plist path, so they would never carry a staging path.
- On macOS `/tmp` and `/var/tmp` are symlinks into `/private`. The substring `/tmp/` already matches both forms; the explicit entries are there for readability.
- `/Users/` is deliberately not matched as a whole, because legitimate per-user LaunchAgents live under it. `/Library/Caches/` is left out for now because some vendor updaters run from there.

## How to test
On a macOS test machine or VM, copy a harmless plist into /tmp and run `launchctl load /tmp/test.plist`, then unload and delete it. Confirm your macOS telemetry captures the full launchctl command line first.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Installers that stage a plist in /tmp or /var/folders before moving it.
- Developer or IT tooling that loads test launchd jobs.

Exclude known installer parents (for example signed package installers) and review the plist contents and program path for each hit.

## Limitations
Does not cover plists loaded from normal LaunchAgents folders. It also misses persistence where a plist is written straight into `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons` and never loaded with launchctl, because launchd picks those up at next login or boot. That is a telemetry boundary: process creation won't show it. Add a companion file-creation rule for `.plist` writes in those folders (Endpoint Security file events or EDR file telemetry), and consider the Background Task Management notifications macOS shows for new login items.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1543/001/
- https://attack.mitre.org/techniques/T1543/004/
