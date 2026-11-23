import dns.resolver
from datetime import datetime
import webbrowser
import os

# استخدام خوادم DNS سريعة لضمان فحص الشركات العملاقة بدون انقطاع المهلة
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                return True, txt
        return False, "No SPF record found"
    except Exception:
        return False, "SPF lookup failed"

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                return ("Weak" if "p=none" in txt else "Strong"), txt
        return "Missing", "No DMARC record found"
    except Exception:
        return "Missing", "DMARC record missing"
def generate_report(domain):
    print(f"\n[*] Auditing email security for: {domain} ...")
    spf_ok, spf_txt = check_spf(domain)
    dmarc_st, dmarc_txt = check_dmarc(domain)

    if spf_ok and dmarc_st == "Strong":
        risk, color, score = "Safe (Low Risk)", "#10b981", "100/100"
    elif spf_ok and dmarc_st in ["Weak", "Missing"]:
        risk, color, score = "Spoofing Possible (Medium Risk)", "#f59e0b", "50/100"
    else:
        risk, color, score = "Vulnerable to Spoofing (High Risk)", "#ef4444", "10/100"

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>Email Audit - {domain}</title>
<style>body{{font-family:Tahoma,sans-serif;background:#0f172a;color:#f8fafc;padding:30px}}
.box{{max-width:800px;margin:auto;background:#1e293b;padding:25px;border-radius:10px}}
.badge{{display:inline-block;padding:8px 15px;border-radius:6px;background:{color};font-weight:bold}}
.card{{background:#0f172a;padding:15px;border-radius:8px;margin-top:15px;border-right:4px solid #38bdf8}}
code{{display:block;background:#020617;color:#38bdf8;padding:10px;margin-top:8px;direction:ltr;text-align:left}}</style></head>
<body><div class="box"><h2>🛡️ تقرير فحص انتحال البريد الإلكتروني: <span dir="ltr">{domain}</span></h2>
<p>التقييم: <strong>{score}</strong> | الحالة: <span class="badge">{risk}</span></p>
<div class="card"><h4>1. سجل SPF: {"✅ مفعل" if spf_ok else "❌ مفقود"}</h4><code>{spf_txt}</code></div>
<div class="card"><h4>2. سجل DMARC: {"✅ قوي" if dmarc_st=="Strong" else "❌ ضعيف أو مفقود"}</h4><code>{dmarc_txt}</code></div>
<div class="card" style="border-color:#10b981"><h4>💡 الحل المقترح للعميل:</h4>
<code>Host: _dmarc.{domain} | Value: v=DMARC1; p=reject;</code></div></div></body></html>"""

    fname = f"email_report_{domain.replace('.', '_')}.html"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Report saved: {fname}")
    webbrowser.open('file://' + os.path.realpath(fname))

if __name__ == "__main__":
    target = input("Enter domain (e.g. google.com): ").strip().replace("https://", "").replace("http://", "").split("/")[0]
    if target:
        generate_report(target)