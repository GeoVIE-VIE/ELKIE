#!/usr/bin/env python3
"""Rebuild Honeypot Threat Overview — clean, actionable, honeypot-only."""
import json, os, requests, urllib3
urllib3.disable_warnings()

TOKEN = os.environ.get("GRAFANA_TOKEN", "")
BASE = "https://localhost:3000"
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

HP = {"type": "elasticsearch", "uid": "ffffy3uxl7ri8b"}
VM = {"type": "elasticsearch", "uid": "efffzddwcadq8e"}
MA = {"type": "elasticsearch", "uid": "efgoujb13qarkd"}

EXT = "NOT src_ip:192.168.* AND NOT src_ip:10.* AND NOT src_ip:172.*"
ACTIVE = "(container.name:cowrie OR container.name:dionaea OR container.name:tanner OR container.name:h0neytr4p)"

y = 0
def ny(h):
    global y; p = y; y += h; return p

def row(t):
    return {"type": "row", "title": t, "gridPos": {"h": 1, "w": 24, "x": 0, "y": ny(1)}, "collapsed": False}

def stat(t, ds, q, x, w=4, mt="count", f=None):
    m = {"id": "1", "type": mt}
    if f: m["field"] = f
    return {"type": "stat", "title": t, "datasource": ds,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y},
        "targets": [{"refId": "A", "query": q, "metrics": [m],
            "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp",
                "settings": {"interval": "1h", "min_doc_count": "0"}}], "timeField": "@timestamp"}],
        "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
            "thresholds": {"steps": [{"color": "green", "value": None}]}}},
        "options": {"reduceOptions": {"calcs": ["sum"]}}}

def pie(t, ds, q, field, x, w=8, h=8):
    p = ny(h) if x == 0 else y - h
    return {"type": "piechart", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                "settings": {"size": "15", "order": "desc", "orderBy": "1", "min_doc_count": 1}}],
            "timeField": "@timestamp"}],
        "options": {"legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value", "percent"]},
            "pieType": "donut", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}}}

def tt(t, ds, q, field, x=0, w=12, h=8, sz="15"):
    """Terms table — single field aggregation."""
    p = ny(h) if x == 0 else y - h
    return {"type": "table", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                "settings": {"size": sz, "order": "desc", "orderBy": "1", "min_doc_count": 1}}],
            "timeField": "@timestamp"}]}

def multi_table(t, ds, q, fields, x=0, w=24, h=8, sz="20"):
    """Multi-field terms table — nested bucket aggs for IP + Port + Honeypot style tables."""
    p = ny(h)
    aggs = []
    for i, (field, size) in enumerate(fields):
        aggs.append({"id": str(i+2), "type": "terms", "field": field,
            "settings": {"size": size, "order": "desc", "orderBy": "1", "min_doc_count": 1}})
    return {"type": "table", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": aggs, "timeField": "@timestamp"}]}

def ts(t, ds, q, x=0, w=24, h=6, split=None):
    aggs = []
    if split:
        aggs.append({"id": "3", "type": "terms", "field": split,
            "settings": {"size": "10", "order": "desc", "orderBy": "1", "min_doc_count": 1}})
    aggs.append({"id": "2", "type": "date_histogram", "field": "@timestamp",
        "settings": {"interval": "auto", "min_doc_count": 0}})
    return {"type": "timeseries", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": ny(h)},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"},
            "custom": {"drawStyle": "line", "fillOpacity": 20, "lineInterpolation": "smooth",
                "lineWidth": 2, "showPoints": "never", "stacking": {"group": "A", "mode": "normal"}}}},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": aggs, "timeField": "@timestamp"}],
        "options": {"legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]},
            "tooltip": {"mode": "multi", "sort": "desc"}}}

def logs(t, ds, q, x=0, w=24, h=6):
    """Logs panel — shows raw events in a readable log format."""
    return {"type": "logs", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": ny(h)},
        "targets": [{"refId": "A", "query": q,
            "metrics": [{"id": "1", "type": "logs", "settings": {"limit": "30"}}],
            "bucketAggs": [], "timeField": "@timestamp"}]}

P = []

# ===== OVERVIEW =====
P.append(row("Honeypot Overview"))
ny(4)
P.append(stat("Total Events", HP, ACTIVE, 0))
P.append(stat("Unique Attackers", HP, f"{EXT} AND {ACTIVE}", 4, mt="cardinality", f="src_ip"))
P.append(stat("Login Attempts", HP, "honeypot.eventid:cowrie.login.success OR honeypot.eventid:cowrie.login.failed", 8))
P.append(stat("Successful Logins", HP, "honeypot.eventid:cowrie.login.success", 12))
P.append(stat("Commands Run", HP, "honeypot.eventid:cowrie.command.input", 16))
P.append(stat("Dionaea Hits", HP, "container.name:dionaea", 20))

P.append(ts("Attack Timeline", HP, ACTIVE, split="container.name"))

# Attacker IP → Honeypot → Port — the money table
P.append(multi_table("Attackers — IP / Honeypot / Country", HP,
    f"{EXT} AND {ACTIVE}",
    [("src_ip", "20"), ("container.name", "5"), ("source.geo.country_name", "3")]))

# ===== COWRIE =====
P.append(row("Cowrie SSH — Port 22"))
P.append(tt("Top Passwords", HP, "honeypot.password:*", "honeypot.password", 0, 8))
P.append(tt("Top Usernames", HP, "honeypot.username:*", "honeypot.username", 8, 8))
P.append(pie("Login Outcome", HP, "honeypot.eventid:cowrie.login.*", "honeypot.eventid", 16, 8))

P.append(tt("Top Commands", HP, "honeypot.eventid:cowrie.command.input", "honeypot.input", 0, 12))
P.append(tt("SSH Client Versions", HP, "honeypot.eventid:cowrie.client.version", "honeypot.version", 12, 12))

# Successful logins: IP → Username → Password
P.append(multi_table("Successful Logins — IP / User / Password", HP,
    "honeypot.eventid:cowrie.login.success",
    [("src_ip", "20"), ("honeypot.username", "3"), ("honeypot.password", "3")]))

# Commands: IP → Command
P.append(multi_table("Commands Executed — IP / Command", HP,
    "honeypot.eventid:cowrie.command.input",
    [("src_ip", "10"), ("honeypot.input", "5")]))

# Tunnel requests: IP → Destination → Port
P.append(multi_table("TCP Tunnels — Attacker / Destination / Port", HP,
    "honeypot.eventid:cowrie.direct-tcpip.request",
    [("src_ip", "10"), ("honeypot.dst_ip", "5"), ("honeypot.dst_port", "3")]))

# ===== DIONAEA =====
P.append(row("Dionaea — Ports 21 (FTP), 3306 (MySQL)"))
ny(4)
P.append(stat("Total Connections", HP, "container.name:dionaea", 0, 6))
P.append(stat("Unique Attackers", HP, f"container.name:dionaea AND {EXT}", 6, 6, mt="cardinality", f="honeypot.src_ip"))
P.append(stat("FTP Sessions", HP, "container.name:dionaea AND honeypot.connection.protocol:ftpd", 12, 6))
P.append(stat("MySQL Sessions", HP, "container.name:dionaea AND honeypot.dst_port:3306", 18, 6))

P.append(ts("Dionaea Timeline", HP, "container.name:dionaea"))

# Dionaea: IP → Port → Protocol
P.append(multi_table("Dionaea — Attacker / Port / Protocol", HP,
    f"container.name:dionaea AND {EXT} AND honeypot.src_ip:*",
    [("honeypot.src_ip", "15"), ("honeypot.dst_port", "3"), ("honeypot.connection.protocol", "3")]))

P.append(tt("MySQL Usernames Tried", HP, "container.name:dionaea AND honeypot.credentials.username:*", "honeypot.credentials.username", 0, 12))
P.append(tt("FTP Commands", HP, "container.name:dionaea AND honeypot.ftp.commands.arguments:*", "honeypot.ftp.commands.arguments", 12, 12))

# ===== WEB =====
P.append(row("Web Honeypots — Tanner (80) + h0neytr4p (443)"))
ny(4)
P.append(stat("Tanner Requests", HP, "container.name:tanner", 0, 6))
P.append(stat("h0neytr4p Requests", HP, "container.name:h0neytr4p", 6, 6))
P.append(stat("Unique Web Attackers", HP, f"(container.name:tanner OR container.name:h0neytr4p) AND {EXT}", 12, 6, mt="cardinality", f="src_ip"))
P.append(stat("Paths Probed", HP, "container.name:tanner AND honeypot.path:*", 18, 6, mt="cardinality", f="honeypot.path"))

# Web attacks: IP → Path → Method
P.append(multi_table("Web Attacks — IP / Path / Method", HP,
    "container.name:tanner AND honeypot.path:*",
    [("honeypot.peer.ip", "15"), ("honeypot.path", "10"), ("honeypot.method", "3")]))

P.append(ts("Web Attack Timeline", HP, "container.name:tanner OR container.name:h0neytr4p", split="container.name"))

# ===== ATTACKER INTEL =====
P.append(row("Attacker Intelligence"))
P.append(pie("By Country", HP, f"source.geo.country_name:* AND {EXT} AND {ACTIVE}", "source.geo.country_name", 0, 12))
P.append(pie("By Honeypot", HP, ACTIVE, "container.name", 12, 12))

# ===== MALWARE =====
P.append(row("Malware Samples"))
ny(4)
P.append(stat("Analyzed", MA, "*", 0, 4))
P.append(stat("ELF", MA, "is_elf:true", 4, 4))
P.append(stat("PE", MA, "is_pe:true", 8, 4))
P.append(stat("YARA Hits", MA, "yara_matches:*", 12, 4))
P.append(stat("VT Known", MA, "virustotal.found:true", 16, 4))
P.append(stat("Critical/High", MA, "severity:critical OR severity:high", 20, 4))

P.append(pie("Classification", MA, "*", "classification", 0, 8))
P.append(pie("Severity", MA, "*", "severity", 8, 8))
P.append(pie("File Types", MA, "*", "mime_type", 16, 8))

# Samples: SHA256 → Type → Classification → Honeypot
P.append(multi_table("Extracted Samples — Hash / Type / Class / Source", MA,
    "*",
    [("sha256", "20"), ("mime_type", "3"), ("classification", "3"), ("source.honeypot", "3")]))

P.append(ts("Extraction Timeline", MA, "*", h=5))

# ===== SACRIFICIAL VM — PAM HONEYPOT =====
P.append(row("Sacrificial VM — SSH Honeypot"))
SV = "log_type:honeypot_auth"
ny(4)
P.append(stat("Total Auth Attempts", VM, SV, 0))
P.append(stat("Successful Logins", VM, f"{SV} AND auth_success:true", 4))
P.append(stat("Failed Attempts", VM, f"{SV} AND auth_success:false", 8))
P.append(stat("Unique IPs", VM, SV, 12, mt="cardinality", f="src_ip.keyword"))
P.append(stat("Unique Usernames", VM, SV, 16, mt="cardinality", f="username.keyword"))
P.append(stat("Unique Passwords", VM, SV, 20, mt="cardinality", f="password.keyword"))

P.append(ts("Auth Attempts Over Time", VM, SV, split="auth_success", h=6))

P.append(tt("Top Source IPs", VM, SV, "src_ip.keyword", 0, 8))
P.append(tt("Top Usernames", VM, SV, "username.keyword", 8, 8))
P.append(tt("Top Passwords", VM, SV, "password.keyword", 16, 8))

P.append(pie("Auth Reasons", VM, SV, "auth_reason.keyword", 0, 8))
P.append(tt("Successful Logins by IP", VM, f"{SV} AND auth_success:true", "src_ip.keyword", 8, 8))
P.append(tt("Successful Credentials", VM, f"{SV} AND auth_success:true", "username.keyword", 16, 8))

P.append(logs("Recent Auth Log", VM, SV, h=8))

# ===== SACRIFICIAL VM — AUDITD =====
P.append(row("Sacrificial VM — Auditd"))
ny(4)
P.append(stat("Auditd Events", VM, "service.type:auditd", 0))
P.append(stat("execve", VM, "event.action.keyword:execve", 4))
P.append(stat("Auth Events", VM, "event.category.keyword:authentication", 8))
P.append(stat("Sessions", VM, "event.category.keyword:session", 12))
P.append(stat("Network", VM, "event.action.keyword:sockaddr", 16))
P.append(stat("Unique Binaries", VM, "event.action.keyword:execve", 20, mt="cardinality", f="process.executable.keyword"))

P.append(ts("Process Activity", VM, "event.action.keyword:execve", split="process.name.keyword", h=6))

P.append(tt("Top Executables", VM, "event.action.keyword:execve", "process.executable.keyword", 0, 12))
P.append(tt("Top Processes", VM, "event.action.keyword:execve", "process.name.keyword", 12, 12))

P.append(tt("Network by Process", VM, "event.action.keyword:sockaddr", "process.name.keyword", 0, 8))
P.append(pie("Audit Keys", VM, "auditd.log.key:*", "auditd.log.key.keyword", 8, 8))
P.append(tt("Auth Users", VM, "event.category.keyword:authentication", "user.name.keyword", 16, 8))

P.append(ts("Auth Timeline", VM, "event.category.keyword:authentication", h=5))

# ===== DEPLOY =====
r = requests.post(f"{BASE}/api/dashboards/db", headers=H, json={
    "dashboard": {
        "title": "Honeypot Threat Overview", "uid": "tpot-attack-overview",
        "tags": ["honeypot", "cowrie", "dionaea", "malware"],
        "timezone": "browser", "refresh": "5m",
        "time": {"from": "now-7d", "to": "now"},
        "panels": P,
    }, "overwrite": True,
}, verify=False, timeout=30).json()

print(f"Status: {r.get('status','?')} v{r.get('version','?')} | {len(P)} panels")
for p in P:
    if p["type"] == "row": print(f"  {p['title']}")
