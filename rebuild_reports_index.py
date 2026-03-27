#!/usr/bin/env python3
"""Regenerate the malware reports index.html from ES metadata."""
import json, os, requests
from datetime import datetime
from pathlib import Path

reports_dir = Path(os.environ.get("REPORTS_DIR", os.environ.get("ELKIE_HOME", "/home/legs") + "/reports"))
es = os.environ.get("ES_URL", "http://localhost:9200")
pdfs = sorted(reports_dir.glob("*_report.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)

samples = {}
for pdf in pdfs:
    sha_prefix = pdf.stem.replace("_report", "")
    try:
        r = requests.post(f"{es}/malware-analysis/_search", json={
            "size": 1, "query": {"prefix": {"sha256": sha_prefix}},
            "_source": ["sha256", "classification", "severity", "file_type", "file_size", "indexed_at", "virustotal"]
        }, timeout=5)
        if r.status_code == 200 and r.json()["hits"]["hits"]:
            samples[sha_prefix] = r.json()["hits"]["hits"][0]["_source"]
    except:
        pass

total = len(pdfs)
classifications = {}
severities = {}
for s in samples.values():
    classifications[s.get("classification", "unknown")] = classifications.get(s.get("classification", "unknown"), 0) + 1
    severities[s.get("severity", "unknown")] = severities.get(s.get("severity", "unknown"), 0) + 1

icons = {"trojan": "\U0001f434", "botnet": "\U0001f916", "miner": "\u26cf\ufe0f", "ransomware": "\U0001f512", "dropper": "\U0001f4a7", "worm": "\U0001f41b"}

html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>ELKIE SOC — Malware Reports</title>'
html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;background:#0a0e17;color:#e0e0e0;min-height:100vh}'
html += '.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-bottom:2px solid #ED4245;text-align:center}.header h1{font-size:28px;color:#fff;letter-spacing:2px}.header h1 span{color:#ED4245}.header p{color:#888;font-size:13px;margin-top:6px}'
html += '.stats{display:flex;justify-content:center;gap:20px;padding:20px;flex-wrap:wrap}.sc{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:15px 25px;text-align:center}.sc .v{font-size:28px;font-weight:700}.sc .l{font-size:11px;color:#888;text-transform:uppercase;margin-top:4px}'
html += '.reports{max-width:1000px;margin:20px auto;padding:0 20px}.report{background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:10px;padding:16px 20px;display:flex;align-items:center;gap:16px;transition:border-color 0.2s;cursor:pointer;text-decoration:none;color:inherit}.report:hover{border-color:#5865F2}'
html += '.report .icon{font-size:28px;min-width:40px;text-align:center}.report .info{flex:1}.report .info h3{font-size:14px;font-family:monospace;margin-bottom:4px}.report .info .meta{font-size:12px;color:#888}.report .tags{display:flex;gap:4px;flex-wrap:wrap}'
html += '.tag{padding:3px 8px;border-radius:4px;font-size:10px;font-weight:600}.tag.critical{background:#3a1a1a;color:#ED4245;border:1px solid #ED4245}.tag.high{background:#3a2a1a;color:#FE8D2F;border:1px solid #FE8D2F}.tag.medium{background:#3a3a1a;color:#FEE75C;border:1px solid #FEE75C}.tag.low{background:#1a3a1a;color:#57F287;border:1px solid #57F287}'
html += '.tag.type{background:#1a1a2e;color:#5865F2;border:1px solid #374151}.tag.vt{background:#2a1a1a;color:#ED4245;border:1px solid #5a2d2d}.report .date{font-size:11px;color:#666;min-width:80px;text-align:right}'
html += '.footer{text-align:center;padding:30px;color:#333;font-size:11px;letter-spacing:2px}</style></head><body>'
html += '<div class="header"><h1><span>ELKIE</span> SOC — Malware Reports</h1><p>Automated Threat Analysis Reports</p></div>'
html += '<div class="stats">'
html += f'<div class="sc"><div class="v" style="color:#5865F2">{total}</div><div class="l">Total</div></div>'
html += f'<div class="sc"><div class="v" style="color:#ED4245">{severities.get("critical",0)}</div><div class="l">Critical</div></div>'
html += f'<div class="sc"><div class="v" style="color:#FE8D2F">{severities.get("high",0)}</div><div class="l">High</div></div>'
for cls, count in sorted(classifications.items(), key=lambda x: -x[1])[:4]:
    html += f'<div class="sc"><div class="v" style="color:#57F287">{count}</div><div class="l">{cls}</div></div>'
html += '</div><div class="reports">'

for pdf in pdfs:
    sha_prefix = pdf.stem.replace("_report", "")
    s = samples.get(sha_prefix, {})
    classification = s.get("classification", "unknown")
    severity = s.get("severity", "unknown")
    file_type = (s.get("file_type", "unknown") or "unknown")[:40]
    file_size = s.get("file_size", 0)
    vt = s.get("virustotal", {})
    icon = icons.get(classification, "\U0001f52c")
    size_str = f"{file_size/1048576:.1f} MB" if file_size > 1048576 else f"{file_size/1024:.0f} KB" if file_size > 1024 else f"{file_size} B"
    vt_tag = f'<span class="tag vt">VT {vt["detections"]}/{vt.get("total","?")}</span>' if vt and vt.get("detections") else ""
    mtime = datetime.fromtimestamp(pdf.stat().st_mtime).strftime("%Y-%m-%d")
    html += f'<a class="report" href="/reports/{pdf.name}" target="_blank"><div class="icon">{icon}</div><div class="info"><h3>{sha_prefix}...</h3><div class="meta">{file_type} — {size_str}</div></div><div class="tags"><span class="tag {severity}">{severity.upper()}</span><span class="tag type">{classification}</span>{vt_tag}</div><div class="date">{mtime}</div></a>'

html += '</div><div class="footer">ELKIE SOC — AUTOMATED MALWARE ANALYSIS</div></body></html>'

with open(reports_dir / "index.html", "w") as f:
    f.write(html)
print(f"Rebuilt: {total} reports")
