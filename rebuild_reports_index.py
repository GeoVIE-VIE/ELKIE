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
            "_source": ["sha256", "md5", "classification", "severity", "file_type", "file_size", "indexed_at", "virustotal"]
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

icons = {"trojan": "\U0001f434", "botnet": "\U0001f916", "miner": "\u26cf\ufe0f", "ransomware": "\U0001f512", "backdoor": "\U0001f6aa", "dropper": "\U0001f4a7", "worm": "\U0001f41b"}

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,sans-serif;background:#0a0e17;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-bottom:2px solid #ED4245;text-align:center}
.header h1{font-size:28px;color:#fff;letter-spacing:2px}
.header h1 span{color:#ED4245}
.header p{color:#888;font-size:13px;margin-top:6px}
.stats{display:flex;justify-content:center;gap:20px;padding:20px;flex-wrap:wrap}
.sc{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:15px 25px;text-align:center}
.sc .v{font-size:28px;font-weight:700}
.sc .l{font-size:11px;color:#888;text-transform:uppercase;margin-top:4px}
.reports{max-width:1000px;margin:20px auto;padding:0 20px}

.report{
  background:#111827;
  border:1px solid #1f2937;
  border-radius:12px;
  padding:12px 14px;
  margin-bottom:10px;
  display:flex;
  align-items:flex-start;
  gap:14px;
  text-decoration:none;
  color:inherit;
  transition:border-color .2s, transform .15s;
}
.report:hover{
  border-color:#5865F2;
  transform:translateY(-1px);
}
.icon{
  flex:0 0 34px;
  font-size:24px;
  line-height:1;
  margin-top:4px;
  display:flex;
  align-items:center;
  justify-content:center;
}
.content{
  flex:1;
  min-width:0;
}
.topline{
  display:flex;
  align-items:center;
  gap:8px;
  min-width:0;
  margin-bottom:6px;
}
.topline h3{
  margin:0;
  font-size:14px;
  font-family:monospace;
  font-weight:800;
  letter-spacing:0.3px;
  color:#f3f4f6;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  flex:0 1 auto;
  max-width:180px;
}
.filemeta{
  min-width:0;
  font-size:11px;
  color:#94a3b8;
  opacity:0.8;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  flex:1 1 auto;
}
.pillbar{
  display:flex;
  align-items:center;
  gap:5px;
  flex-wrap:wrap;
}
.tag{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  padding:3px 7px;
  border-radius:6px;
  font-size:9px;
  font-weight:700;
  line-height:1;
  white-space:nowrap;
  text-transform:uppercase;
  text-decoration:none;
}
.tag.critical{background:#3a1a1a;color:#ED4245;border:1px solid #ED4245}
.tag.high{background:#3a2a1a;color:#FE8D2F;border:1px solid #FE8D2F}
.tag.medium{background:#3a3a1a;color:#FEE75C;border:1px solid #FEE75C}
.tag.low{background:#1a3a1a;color:#57F287;border:1px solid #57F287}
.tag.unknown{background:#1a1a1a;color:#888;border:1px solid #333}
.tag.type{background:#1a1a2e;color:#8ea1ff;border:1px solid #374151}
.tag.vt{background:#2a1a1a;color:#ED4245;border:1px solid #5a2d2d}
.tag.artifact{background:#0f1f17;color:#57F287;border:1px solid #1f4d2f;opacity:0.8;cursor:pointer}
.tag.artifact:hover{background:#1d3a27;color:#fff;opacity:1}
.tag.date{margin-left:8px;background:#151b26;color:#9ca3af;border:1px solid #2a3441;text-transform:none;opacity:0.7}

.footer{text-align:center;padding:30px;color:#333;font-size:11px;letter-spacing:2px}

@media(max-width:760px){
  .topline{flex-direction:column;align-items:flex-start;gap:4px}
  .topline h3,.filemeta{max-width:100%}
  .tag.date{margin-left:0}
}
"""

html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ELKIE SOC — Malware Reports</title>
<style>{CSS}</style></head><body>
"""

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
    mtime = datetime.fromtimestamp(pdf.stat().st_mtime).strftime("%Y-%m-%d")

    vt_tag = ""
    if vt and vt.get("detections"):
        vt_tag = f'<span class="tag vt">VT {vt["detections"]}/{vt.get("total","?")}</span>'

    pcap_tag = ""
    strace_tag = ""
    pcap_path = reports_dir / f"{sha_prefix}_capture.pcap"
    strace_path = reports_dir / f"{sha_prefix}_strace.log"
    if pcap_path.exists():
        pcap_tag = f'<span class="tag artifact" onclick="event.preventDefault();event.stopPropagation();window.open(\'/reports/{sha_prefix}_capture.pcap\')">PCAP</span>'
    if strace_path.exists():
        strace_tag = f'<span class="tag artifact" onclick="event.preventDefault();event.stopPropagation();window.open(\'/reports/{sha_prefix}_strace.log\')">STRACE</span>'

    html += (
        f'<a class="report" href="/reports/{pdf.name}" target="_blank">'
        f'<div class="icon">{icon}</div>'
        f'<div class="content">'
        f'<div class="topline">'
        f'<h3>{sha_prefix}...</h3>'
        f'<div class="filemeta">{file_type} — {size_str}</div>'
        f'</div>'
        f'<div class="pillbar">'
        f'<span class="tag {severity}">{severity.upper()}</span>'
        f'<span class="tag type">{classification}</span>'
        f'{vt_tag}{pcap_tag}{strace_tag}'
        f'<span class="tag date">{mtime}</span>'
        f'</div>'
        f'</div>'
        f'</a>'
    )

html += '</div><div class="footer">ELKIE SOC — AUTOMATED MALWARE ANALYSIS</div></body></html>'

with open(reports_dir / "index.html", "w") as f:
    f.write(html)
print(f"Rebuilt: {total} reports")
