# Secure Email Authentication Gateway: SPF, DKIM, DMARC

## Files
| File | Purpose |
|---|---|
| `email_auth_toolkit.py` | CLI: key generation, DNS record output, DKIM signing, header analysis |
| `header_analyzer.html` | Browser tool: paste raw headers, get a parsed authentication summary |

## Setup
```bash
pip install dkimpy dnspython cryptography pyspf
```

## Runbook

### 1. Generate the DKIM key pair
```bash
python email_auth_toolkit.py keygen --out dkim_private.pem
```
The private key is created with mode 600. Keep it on the signing host only.

### 2. Print the DNS records
```bash
python email_auth_toolkit.py records --domain example.com --selector s1 --ip 203.0.113.10
```
Publish the three TXT records at your DNS provider:
- SPF at `example.com`
- DKIM at `s1._domainkey.example.com`
- DMARC at `_dmarc.example.com`, starting with `p=none`

Verify propagation:
```bash
dig +short TXT example.com
dig +short TXT s1._domainkey.example.com
dig +short TXT _dmarc.example.com
```

### 3. Sign a test email
```bash
python email_auth_toolkit.py sign test.eml --domain example.com --selector s1
```
Send `test.signed.eml` through your MTA (or a Gmail/Outlook test account) from the authorized IP.

### 4. Analyze the received message
Save the message from the recipient mailbox ("Show original") as `received.eml`, then:
```bash
python email_auth_toolkit.py analyze received.eml --live --ip 203.0.113.10
```
Exit code is 0 if DMARC would pass, 1 otherwise, so it can be used in CI or monitoring scripts.
For the web tool, open `header_analyzer.html` and paste the headers.

### 5. DMARC rollout
| Stage | Policy | Move on when |
|---|---|---|
| Monitor | `p=none; rua=...` | 2 to 4 weeks of aggregate reports show every legitimate source passing SPF or DKIM **aligned** |
| Ramp | `p=quarantine; pct=25`, then 50, 100 | No legitimate mail is landing in spam |
| Enforce | `p=reject` | Ongoing review of reports |

## How the protocols interlock
- **SPF** checks that the connecting IP may send for the envelope domain (Return-Path).
- **DKIM** checks a cryptographic signature over selected headers and the body, tied to the `d=` domain.
- **DMARC** requires SPF *or* DKIM to pass **and align** with the visible `From:` domain, then tells receivers what to do on failure. SPF and DKIM alone do not protect the From address a user sees; DMARC alignment does.

## Notes and limitations
- Organizational-domain matching is naive (last two labels). Use the Public Suffix List (`tldextract`) for domains like `example.co.uk`.
- The header analyzer trusts the `Authentication-Results` header written by the receiving server. Only trust the one added by your own provider, since senders can forge others. Use `--live` to re-verify DKIM independently.
- Forwarding and mailing lists commonly break SPF; consider ARC for those flows.
- Rotate DKIM keys periodically (new selector, publish, switch signing, retire the old one).
