#!/usr/bin/env python3
"""
MailCheck -- cold email deliverability & domain health checker.

Checks, for a given sending domain:
  - SPF record present and syntactically sane
  - DKIM record present at common selector names (best-effort guess list)
  - DMARC record present and its policy (none/quarantine/reject)
  - MX records resolve
  - Reverse DNS / PTR sanity is out of scope (needs sending IP, not domain)

Also scans an email body/subject for common spam-trigger words and
gives a rough deliverability risk score.

Zero paid dependencies -- uses the system `dig` binary via subprocess.
"""
import argparse
import json
import re
import subprocess
import sys

COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "dkim", "mail",
    "default", "smtp", "s1", "s2", "zoho", "mandrill", "sendgrid",
]

SPAM_TRIGGER_WORDS = [
    "free", "guarantee", "act now", "limited time", "click here",
    "buy now", "cash", "cheap", "credit", "no obligation", "risk-free",
    "winner", "congratulations", "urgent", "double your", "earn money",
    "work from home", "100% free", "no cost", "amazing", "miracle",
    "cancel at any time", "increase sales", "lowest price", "eliminate debt",
    "get paid", "extra income", "once in a lifetime", "special promotion",
]

EXCESSIVE_PUNCT_RE = re.compile(r"[!]{2,}|[?]{2,}")
ALL_CAPS_WORD_RE = re.compile(r"\b[A-Z]{4,}\b")


def dig(record_type, domain):
    try:
        out = subprocess.run(
            ["dig", "+short", record_type, domain],
            capture_output=True, text=True, timeout=8,
        )
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        return lines
    except Exception as e:
        return [f"ERROR: {e}"]


def check_domain(domain):
    result = {"domain": domain, "checks": {}}

    # MX
    mx = dig("MX", domain)
    result["checks"]["mx"] = {
        "found": bool(mx) and not mx[0].startswith("ERROR"),
        "records": mx,
    }

    # SPF (in TXT records)
    txt = dig("TXT", domain)
    spf_records = [t for t in txt if "v=spf1" in t.lower()]
    result["checks"]["spf"] = {
        "found": bool(spf_records),
        "records": spf_records,
        "issue": None,
    }
    if len(spf_records) > 1:
        result["checks"]["spf"]["issue"] = "multiple SPF records found -- only one is allowed, this breaks SPF"
    elif spf_records:
        rec = spf_records[0]
        has_all_mechanism = "~all" in rec or "-all" in rec or "?all" in rec
        has_redirect = "redirect=" in rec.lower()
        if not has_all_mechanism and not has_redirect:
            result["checks"]["spf"]["issue"] = "SPF record has no enforcement mechanism (~all or -all) and no redirect= -- weak protection"

    # DMARC
    dmarc = dig("TXT", f"_dmarc.{domain}")
    dmarc_records = [t for t in dmarc if "v=dmarc1" in t.lower()]
    policy = None
    if dmarc_records:
        m = re.search(r"p=(\w+)", dmarc_records[0], re.IGNORECASE)
        if m:
            policy = m.group(1).lower()
    result["checks"]["dmarc"] = {
        "found": bool(dmarc_records),
        "records": dmarc_records,
        "policy": policy,
    }

    # DKIM -- best effort guess across common selectors
    dkim_found_selectors = []
    for sel in COMMON_DKIM_SELECTORS:
        recs = dig("TXT", f"{sel}._domainkey.{domain}")
        real = [r for r in recs if "v=dkim1" in r.lower() or "p=" in r.lower()]
        if real:
            dkim_found_selectors.append(sel)
    result["checks"]["dkim"] = {
        "found": bool(dkim_found_selectors),
        "selectors_checked": COMMON_DKIM_SELECTORS,
        "selectors_found": dkim_found_selectors,
        "note": "DKIM selectors are provider-specific; absence here does not prove no DKIM exists, only that none of the common selectors were found",
    }

    # Score
    score = 0
    max_score = 4
    if result["checks"]["mx"]["found"]:
        score += 1
    if result["checks"]["spf"]["found"] and not result["checks"]["spf"]["issue"]:
        score += 1
    if result["checks"]["dmarc"]["found"]:
        score += 1
    if result["checks"]["dkim"]["found"]:
        score += 1
    result["deliverability_score"] = f"{score}/{max_score}"
    result["score_raw"] = score

    return result


def check_copy(text):
    text_lower = text.lower()
    found_triggers = [w for w in SPAM_TRIGGER_WORDS if w in text_lower]
    excessive_punct = bool(EXCESSIVE_PUNCT_RE.search(text))
    caps_words = ALL_CAPS_WORD_RE.findall(text)

    risk_points = len(found_triggers) + (2 if excessive_punct else 0) + len(caps_words)
    if risk_points == 0:
        risk = "low"
    elif risk_points <= 3:
        risk = "medium"
    else:
        risk = "high"

    return {
        "spam_trigger_words_found": found_triggers,
        "excessive_punctuation": excessive_punct,
        "all_caps_words": caps_words,
        "risk_level": risk,
        "risk_points": risk_points,
    }


def main():
    parser = argparse.ArgumentParser(description="MailCheck -- cold email deliverability checker")
    parser.add_argument("domain", nargs="?", help="Domain to check (SPF/DKIM/DMARC/MX)")
    parser.add_argument("--copy", help="Path to a text file with email subject+body to scan for spam triggers")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of human-readable report")
    parser.add_argument("--batch", help="[PRO] Path to a file with one domain per line; checks all")
    parser.add_argument("--html", help="[PRO] Write a shareable HTML report to this path")
    args = parser.parse_args()

    if not args.domain and not args.copy and not args.batch:
        parser.error("provide a domain, --copy, --batch, or both")

    output = {}
    # --- PRO: batch mode ---
    if args.batch:
        domains=[l.strip() for l in open(args.batch) if l.strip() and not l.startswith("#")]
        results=[check_domain(d) for d in domains]
        if args.html:
            _write_html(results, args.html); print(f"HTML report written: {args.html}")
        if args.json:
            print(json.dumps(results, indent=2)); return
        print(f"\n=== MailCheck batch: {len(results)} domains ===")
        for r in sorted(results, key=lambda x: x["deliverability_score"]):
            print(f"  {r['deliverability_score']:>3}  {r['domain']}")
        return
    if args.domain:
        output["domain_check"] = check_domain(args.domain)
    if args.copy:
        with open(args.copy) as f:
            text = f.read()
        output["copy_check"] = check_copy(text)

    if args.json:
        print(json.dumps(output, indent=2))
        return

    if "domain_check" in output:
        d = output["domain_check"]
        print(f"\n=== MailCheck: {d['domain']} ===")
        print(f"Deliverability score: {d['deliverability_score']}")
        print(f"  MX:     {'OK' if d['checks']['mx']['found'] else 'MISSING'}")
        spf = d["checks"]["spf"]
        print(f"  SPF:    {'OK' if spf['found'] else 'MISSING'}" + (f"  [!] {spf['issue']}" if spf["issue"] else ""))
        dmarc = d["checks"]["dmarc"]
        print(f"  DMARC:  {'OK (policy=' + str(dmarc['policy']) + ')' if dmarc['found'] else 'MISSING'}")
        dkim = d["checks"]["dkim"]
        print(f"  DKIM:   {'OK (selectors: ' + ', '.join(dkim['selectors_found']) + ')' if dkim['found'] else 'not found at common selectors'}")

    if "copy_check" in output:
        c = output["copy_check"]
        print(f"\n=== Copy spam-risk scan ===")
        print(f"Risk level: {c['risk_level']} (points: {c['risk_points']})")
        if c["spam_trigger_words_found"]:
            print(f"  Trigger words found: {', '.join(c['spam_trigger_words_found'])}")
        if c["excessive_punctuation"]:
            print(f"  Excessive punctuation detected (!! or ??)")
        if c["all_caps_words"]:
            print(f"  ALL-CAPS words: {', '.join(c['all_caps_words'][:10])}")
        if c["risk_points"] == 0:
            print("  No obvious spam triggers found.")

    print()



def _write_html(results, path):
    rows=""
    for r in results:
        c=r["checks"]; sc=r["deliverability_score"]
        color="#16a34a" if "4/4" in str(sc) else ("#ca8a04" if "3/4" in str(sc) else "#dc2626")
        rows+=f'<tr><td>{r["domain"]}</td><td style="color:{color};font-weight:700">{sc}</td>'
        rows+=f'<td>{"OK" if c["mx"]["found"] else "MISSING"}</td>'
        rows+=f'<td>{"OK" if c["spf"]["found"] else "MISSING"}</td>'
        rows+=f'<td>{"OK ("+str(c["dmarc"]["policy"])+")" if c["dmarc"]["found"] else "MISSING"}</td>'
        rows+=f'<td>{"OK" if c["dkim"]["found"] else "not found"}</td></tr>'
    html=f"""<!doctype html><meta charset=utf-8><title>MailCheck Report</title>
<style>body{{font-family:-apple-system,system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;color:#111}}
h1{{font-size:22px}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #eee}}th{{background:#fafafa}}
.foot{{margin-top:24px;color:#888;font-size:12px}}</style>
<h1>MailCheck deliverability report</h1>
<p>{len(results)} domain(s) checked. Higher score = better inbox placement.</p>
<table><tr><th>Domain</th><th>Score</th><th>MX</th><th>SPF</th><th>DMARC</th><th>DKIM</th></tr>
{rows}</table>
<p class=foot>Generated by MailCheck. Fix issues before you send — not after your list is burned.</p>"""
    open(path,"w").write(html)


if __name__ == "__main__":
    main()
