# Detection Engineering Portfolio

Detection rules for threat hunting and incident response, written in [Sigma](https://github.com/SigmaHQ/sigma) and mapped to MITRE ATT&CK. Each rule comes with a write-up covering the logic, a test plan, expected false positives, and known blind spots.

I'm a security engineer with 5+ years in detection engineering, threat hunting, and threat intelligence (Securonix, Splunk). This repo is where I keep detections I can share publicly.

## Rules

| Rule | ATT&CK | Tactic | Platform | Severity | Status |
|---|---|---|---|---|---|
| [LSASS Memory Dump via comsvcs.dll MiniDump](detections/credential-access/lsass-dump-comsvcs-minidump.yml) | T1003.001 | Credential Access | Windows | High | Draft |
| [Office Application Spawning Encoded PowerShell](detections/execution/office-spawns-encoded-powershell.yml) | T1059.001, T1204.002 | Execution | Windows | High | Draft |
| [Scheduled Task Created with User-Writable Path or Script Host](detections/persistence/schtasks-create-suspicious-action.yml) | T1053.005 | Persistence | Windows | Medium | Draft |
| [macOS launchctl Loading a Job from a Temporary or Shared Path](detections/persistence/macos-launchctl-load-from-temp.yml) | T1543.001, T1543.004 | Persistence | macOS | Medium | Draft |
| [Windows Event Log Cleared via wevtutil or PowerShell](detections/defense-evasion/windows-event-log-cleared.yml) | T1070.001 | Defense Evasion | Windows | High | Draft |
| [AWS CloudTrail Logging Stopped or Modified](detections/defense-evasion/aws-cloudtrail-logging-disabled.yml) | T1562.008 | Defense Evasion | AWS | High | Draft |
| [PsExec Service Installed on Host](detections/lateral-movement/psexec-service-installed.yml) | T1021.002, T1569.002 | Lateral Movement | Windows | Medium | Draft |

**Status key:** *Draft* means written and syntax-checked but not yet validated in a lab. *Validated* means tested against a simulated technique, with the result recorded in the rule's write-up.

## How each rule is documented

Every rule folder holds two files with the same name:

- `rule-name.yml`: the Sigma rule
- `rule-name.md`: ATT&CK mapping, required log fields, test plan, false positives and tuning, limitations, and validation results

## Using the rules

Convert a rule for your SIEM with [sigma-cli](https://github.com/SigmaHQ/sigma-cli). For example, for Splunk:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p splunk_windows detections/credential-access/lsass-dump-comsvcs-minidump.yml
```

Other backends (Elastic, Microsoft Sentinel, and more) work the same way. Field names depend on your log source and pipeline, so check them against your own data before deploying.

## Quality checks

A GitHub Actions workflow in `.github/workflows` runs `sigma check` on every push and pull request to catch malformed rules.

## Repository layout

```
detections/   Sigma rules grouped by MITRE ATT&CK tactic
docs/         Notes and supporting documentation
```

## Roadmap

- Validate each draft rule in a lab and record the results
- Add rules for Initial Access, Privilege Escalation, and Discovery
- Add cloud identity detections (token and key abuse)
- Add automated conversion and rule tests to the CI workflow

## Disclaimer

These rules are examples for learning and portfolio purposes. Test and tune them against your own environment before using them in production.

## Contact

[LinkedIn](https://www.linkedin.com/in/faraaz-khan/)

*Last updated: November 2026*
