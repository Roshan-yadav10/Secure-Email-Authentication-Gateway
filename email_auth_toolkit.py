#!/usr/bin/env python3
"""Email authentication toolkit: SPF / DKIM / DMARC.

Subcommands:
  keygen   Generate a DKIM RSA key pair
  records  Print the SPF, DKIM and DMARC DNS records to publish
  sign     DKIM-sign a raw .eml message
  analyze  Parse headers and summarize SPF/DKIM/DMARC results (optionally live-verify)

Install: pip install dkimpy dnspython cryptography pyspf
"""
import argparse
import base64
import email
import os
import re
import sys
from email import policy
from email.utils import parseaddr

# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #

def cmd_keygen(args):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Create with 0600 so the private key is never world-readable.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    print(f"Private key written to {args.out} (mode 600). Keep it off DNS and out of git.")
    print(f"Public key (p=): {public_key_b64(args.out)}")


def public_key_b64(private_pem_path):
    from cryptography.hazmat.primitives import serialization

    with open(private_pem_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


# --------------------------------------------------------------------------- #
# DNS record generation
# --------------------------------------------------------------------------- #

def cmd_records(args):
    ips = " ".join(f"ip4:{ip}" if ":" not in ip else f"ip6:{ip}" for ip in args.ip)
    print(f"; --- SPF (publish on {args.domain}) ---")
    print(f'{args.domain}. IN TXT "v=spf1 {ips} -all"')
    print("; Use ~all while testing, -all once every legitimate sender is listed.\n")

    print(f"; --- DKIM (selector '{args.selector}') ---")
    pub = public_key_b64(args.key)
    chunks = [pub[i:i + 200] for i in range(0, len(pub), 200)]  # 255-char TXT limit
    value = "".join(f'"{c}"' for c in ["v=DKIM1; k=rsa; p=" + chunks[0]] + chunks[1:])
    print(f"{args.selector}._domainkey.{args.domain}. IN TXT {value}\n")

    print("; --- DMARC rollout ---")
    rua = f"; rua=mailto:dmarc-reports@{args.domain}"
    stages = [
        ("1. Monitor", f"v=DMARC1; p=none{rua}; adkim=r; aspf=r"),
        ("2. Quarantine ramp", f"v=DMARC1; p=quarantine; pct=25{rua}"),
        ("3. Enforce", f"v=DMARC1; p=reject{rua}"),
    ]
    for label, txt in stages:
        print(f"; {label}")
        print(f'_dmarc.{args.domain}. IN TXT "{txt}"')


# --------------------------------------------------------------------------- #
# DKIM signing
# --------------------------------------------------------------------------- #

def cmd_sign(args):
    import dkim

    with open(args.message, "rb") as fh:
        raw = fh.read()
    with open(args.key, "rb") as fh:
        private = fh.read()
    headers = [b"from", b"to", b"subject", b"date", b"message-id"]
    sig = dkim.sign(
        raw,
        selector=args.selector.encode(),
        domain=args.domain.encode(),
        privkey=private,
        include_headers=headers,
        canonicalize=(b"relaxed", b"relaxed"),
    )
    out = args.output or args.message.replace(".eml", "") + ".signed.eml"
    with open(out, "wb") as fh:
        fh.write(sig + raw)
    print(f"Signed message written to {out}")


# --------------------------------------------------------------------------- #
# Header analysis
# --------------------------------------------------------------------------- #

RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)
TAG_RE = re.compile(r"\b([a-z]+)=([^;]+)")


def org_domain(domain):
    """Naive organizational domain (last two labels).

    Production code should use the Public Suffix List (e.g. `tldextract`)
    so that example.co.uk is handled correctly.
    """
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:])


def aligned(a, b, strict=False):
    if not a or not b:
        return False
    return a.lower() == b.lower() if strict else org_domain(a) == org_domain(b)


def domain_of(header_value):
    addr = parseaddr(header_value or "")[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def analyze_headers(raw):
    msg = email.message_from_bytes(raw, policy=policy.default)
    report = {"results": {}, "notes": []}

    for ar in msg.get_all("Authentication-Results", []):
        for mech, res in RESULT_RE.findall(str(ar)):
            report["results"].setdefault(mech.lower(), res.lower())

    spf_hdr = str(msg.get("Received-SPF", ""))
    if spf_hdr and "spf" not in report["results"]:
        report["results"]["spf"] = spf_hdr.split()[0].lower()

    from_dom = domain_of(msg.get("From"))
    rpath_dom = domain_of(msg.get("Return-Path"))
    dkim_doms = []
    for sig in msg.get_all("DKIM-Signature", []):
        tags = dict(TAG_RE.findall(str(sig).replace("\n", " ")))
        dkim_doms.append((tags.get("d", "").strip(), tags.get("s", "").strip()))

    report.update(from_domain=from_dom, return_path_domain=rpath_dom, dkim_signatures=dkim_doms)
    report["spf_aligned"] = aligned(from_dom, rpath_dom)
    report["dkim_aligned"] = any(aligned(from_dom, d) for d, _ in dkim_doms)

    r = report["results"]
    dmarc_ok = (r.get("spf") == "pass" and report["spf_aligned"]) or (
        r.get("dkim") == "pass" and report["dkim_aligned"]
    )
    report["dmarc_would_pass"] = dmarc_ok

    if not report["results"]:
        report["notes"].append("No Authentication-Results header found (header may be stripped).")
    if r.get("spf") == "pass" and not report["spf_aligned"]:
        report["notes"].append("SPF passed but Return-Path does not align with From: (DMARC will not credit it).")
    if r.get("dkim") == "pass" and not report["dkim_aligned"]:
        report["notes"].append("DKIM passed but d= does not align with From: (DMARC will not credit it).")
    return report


def live_checks(raw, report, ip=None):
    """Re-verify DKIM and look up SPF/DMARC policy from real DNS."""
    import dkim
    import dns.resolver

    report["live_dkim"] = "pass" if dkim.verify(raw) else "fail"

    def txt(name):
        try:
            return ["".join(s.decode() for s in r.strings) for r in dns.resolver.resolve(name, "TXT")]
        except Exception:
            return []

    dom = report["from_domain"]
    report["spf_record"] = next((t for t in txt(dom) if t.startswith("v=spf1")), None)
    report["dmarc_record"] = next((t for t in txt(f"_dmarc.{dom}") if t.startswith("v=DMARC1")), None)

    if ip and report["return_path_domain"]:
        try:
            import spf
            res, _, expl = spf.check2(ip, f"postmaster@{report['return_path_domain']}", report["return_path_domain"])
            report["live_spf"] = res
        except ImportError:
            report["notes"].append("Install pyspf to evaluate SPF for --ip.")


def cmd_analyze(args):
    raw = sys.stdin.buffer.read() if args.file == "-" else open(args.file, "rb").read()
    report = analyze_headers(raw)
    if args.live:
        live_checks(raw, report, args.ip)

    r = report["results"]
    print(f"From domain        : {report['from_domain']}")
    print(f"Return-Path domain : {report['return_path_domain']}")
    print(f"SPF / DKIM / DMARC : {r.get('spf', '-')} / {r.get('dkim', '-')} / {r.get('dmarc', '-')}")
    print(f"SPF aligned        : {report['spf_aligned']}")
    print(f"DKIM aligned       : {report['dkim_aligned']}")
    print(f"DMARC would pass   : {report['dmarc_would_pass']}")
    for d, s in report["dkim_signatures"]:
        print(f"DKIM signature     : d={d} s={s}")
    for key in ("live_dkim", "live_spf", "spf_record", "dmarc_record"):
        if key in report:
            print(f"{key:<19}: {report[key]}")
    for note in report["notes"]:
        print(f"! {note}")
    return 0 if report["dmarc_would_pass"] else 1


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("--out", default="dkim_private.pem")
    k.add_argument("--bits", type=int, default=2048); k.set_defaults(fn=cmd_keygen)

    r = sub.add_parser("records"); r.add_argument("--domain", required=True)
    r.add_argument("--selector", default="s1"); r.add_argument("--key", default="dkim_private.pem")
    r.add_argument("--ip", nargs="+", required=True, help="authorized sender IPs"); r.set_defaults(fn=cmd_records)

    s = sub.add_parser("sign"); s.add_argument("message"); s.add_argument("--domain", required=True)
    s.add_argument("--selector", default="s1"); s.add_argument("--key", default="dkim_private.pem")
    s.add_argument("--output"); s.set_defaults(fn=cmd_sign)

    a = sub.add_parser("analyze"); a.add_argument("file", help=".eml file or - for stdin")
    a.add_argument("--live", action="store_true", help="re-verify DKIM and query DNS")
    a.add_argument("--ip", help="connecting IP for live SPF evaluation"); a.set_defaults(fn=cmd_analyze)
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    sys.exit(args.fn(args) or 0)
