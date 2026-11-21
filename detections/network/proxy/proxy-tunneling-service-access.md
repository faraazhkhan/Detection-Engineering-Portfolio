# Web Proxy Request to a Tunneling Service

| | |
|---|---|
| **MITRE ATT&CK** | T1572 |
| **Tactic** | Command and Control |
| **Severity** | Medium |
| **Log source** | Web proxy or secure web gateway logs |
| **Required fields** | cs-host (requested host), c-ip (client), c-uri, user, action |
| **Rule file** | [`proxy-tunneling-service-access.yml`](./proxy-tunneling-service-access.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects web requests to well-known tunneling services (such as ngrok and Cloudflare quick tunnels) that attackers use to relay traffic, expose internal services, or move data out.

## Detection logic
The requested host name ends with the domain of a known public tunneling service: ngrok, Cloudflare quick tunnels, Serveo, localtunnel, localhost.run (`lhr.life`) or PageKite. These services give a machine inside a network a public address, which attackers use to reach it or to send data out.

## How to test
From a test machine behind your proxy, browse to a free tunnel URL you create yourself (for example a throwaway ngrok tunnel to a local test page), then check the proxy log. Remove the tunnel afterwards.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Developers and IT staff who use tunnels to test or demo applications.

Allow-list developer groups or hosts that legitimately use tunnels. Treat hits from servers or non-developer workstations as higher priority.

## Limitations
The domain list is short and goes out of date, because new tunneling services appear often. Field names vary by proxy vendor, so map `cs-host` to your product (for example the URL or host field in your proxy). Encrypted traffic may only show the host name, not the full URL.

- Self-hosted tools such as FRP, Chisel or bore run on the attacker's own server, so there is no fixed tunnel domain to list. A custom domain pointed at a tunnel service also gets past a suffix match.
- With encrypted traffic, a proxy may only see the outer host name or SNI. Pair proxy logs with DNS query logs and look for long-lived, high-volume connections to rare destinations.
- The list needs regular upkeep as services change their domains. I added several common ones, but verify them against current service domains before relying on them.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1572/
