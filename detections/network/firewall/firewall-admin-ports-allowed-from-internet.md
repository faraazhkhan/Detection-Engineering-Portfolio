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
A traffic log entry with action allow, destination port 3389 (RDP), 22 (SSH), 445 (SMB) or 23 (Telnet), and a source address that is not an internal or special-use address. The exclusion list covers the private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, link-local, carrier-grade NAT (100.64.0.0/10), multicast and reserved ranges, and the IPv6 equivalents (unique local, link-local and loopback). Anything left is treated as the internet.

## How to test
In a test environment, send a connection from an external test address to a lab host on port 3389 or 22 through a firewall rule that allows it, then check the traffic log. Do not open these ports on a production firewall to test.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Intentionally published services, such as a bastion host or a VPN gateway that listens on SSH.
- Approved vendor or partner access.

List the hosts that are meant to be reachable (bastions, VPN gateways) and exclude them. Anything else is an exposure to review. Add more ports, such as 5985/5986 (WinRM) or 1433 (SQL), if they matter to your environment.

## Limitations
- Only shows traffic the firewall allowed, not whether the service answered or the login succeeded. Correlate with authentication and VPN logs, and with how important the destination host is.
- Only the four listed ports are covered. Attackers and misconfigurations also expose admin services on non-standard ports.
- The rule has no direction or session-state field. Depending on your firewall's log format, an allowed connection attempt can look the same as an established session.
- Palo Alto field names differ from the generic ones (for example `dport` for `dst_port`), so map them in your pipeline.
- Address ranges your organization uses internally that are not in the list (for example public space you own) need extra exclusions.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1133/
