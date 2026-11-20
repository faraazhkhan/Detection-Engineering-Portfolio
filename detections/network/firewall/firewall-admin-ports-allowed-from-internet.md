# Firewall Allowed Inbound RDP, SSH, SMB or Telnet from the Internet

| | |
|---|---|
| **MITRE ATT&CK** | T1133 |
| **Tactic** | Initial Access |
| **Severity** | High |
| **Log source** | Firewall traffic logs (for example Palo Alto NGFW traffic logs) |
| **Required fields** | action, src_ip, dst_ip, dst_port (Palo Alto NGFW traffic log fields: action, src, dst, dport, app) |
| **Rule file** | [`firewall-admin-ports-allowed-from-internet.yml`](./firewall-admin-ports-allowed-from-internet.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects firewall logs showing remote administration or file-sharing ports (RDP, SSH, SMB, Telnet) allowed from a public IP address to an internal host, an exposure that attackers actively scan for.

## Detection logic
A traffic log entry with action allow, destination port 3389, 22, 445 or 23, and a source address outside the private ranges.

## How to test
In a test environment, send a connection from an external test address to a lab host on port 3389 or 22 through a firewall rule that allows it, then check the traffic log. Do not open these ports on a production firewall to test.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Intentionally published services, such as a bastion host or a VPN gateway that listens on SSH.
- Approved vendor or partner access.

List the hosts that are meant to be reachable (bastions, VPN gateways) and exclude them. Anything else is an exposure to review. Add more ports, such as 5985/5986 (WinRM) or 1433 (SQL), if they matter to your environment.

## Limitations
Only shows traffic the firewall allowed, not whether the service answered. Palo Alto field names differ from the generic ones (for example `dport` for `dst_port`), so map them in your pipeline. Public ranges that are not private (for example some carrier-grade NAT space) may need extra exclusions.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1133/
