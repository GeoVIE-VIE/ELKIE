#!/usr/bin/env python3
"""Rebuild Honeypot Threat Overview — only uses verified fields."""
import json, os, requests, urllib3
urllib3.disable_warnings()

TOKEN = os.environ.get("GRAFANA_TOKEN", "")
BASE = os.environ.get("GRAFANA_URL", "https://localhost:3000")
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

HP = {"type": "elasticsearch", "uid": os.environ.get("GRAFANA_DS_FILEBEAT_UID", "ffffy3uxl7ri8b")}  # filebeat-*
MA = {"type": "elasticsearch", "uid": os.environ.get("GRAFANA_DS_MALWARE_UID", "efgoujb13qarkd")}  # malware-analysis

# Verified queries — agent names from env
_agent = os.environ.get("SACRIFICIAL_AGENT_NAME", "ds-prod-web01")
_agent_alt = os.environ.get("SACRIFICIAL_AGENT_ALT", "prodction1")
SV = "log_type:honeypot_auth"
AQ = f"service.type:auditd AND (agent.name:{_agent} OR agent.name:{_agent_alt})"
EXT = "NOT src_ip:192.168.* AND NOT src_ip:10.* AND NOT src_ip:172.*"
CONTAINERS = "(container.name:cowrie OR container.name:dionaea OR container.name:tanner OR container.name:h0neytr4p)"

y = 0
def ny(h):
    global y; p = y; y += h; return p

def row(t):
    return {"type": "row", "title": t, "gridPos": {"h": 1, "w": 24, "x": 0, "y": ny(1)}, "collapsed": False}

def stat(t, ds, q, x, w=4, mt="count", f=None, color="green", tf="@timestamp"):
    m = {"id": "1", "type": mt}
    if f: m["field"] = f
    return {"type": "stat", "title": t, "datasource": ds,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y},
        "targets": [{"refId": "A", "query": q, "metrics": [m],
            "bucketAggs": [{"id": "2", "type": "date_histogram", "field": tf,
                "settings": {"interval": "1h", "min_doc_count": "0"}}], "timeField": tf}],
        "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
            "thresholds": {"steps": [{"color": color, "value": None}]}}},
        "options": {"reduceOptions": {"calcs": ["sum"]}}}

def pie(t, ds, q, field, x, w=8, h=8, tf="@timestamp"):
    p = ny(h) if x == 0 else y - h
    return {"type": "piechart", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                "settings": {"size": "15", "order": "desc", "orderBy": "1", "min_doc_count": 1}}],
            "timeField": tf}],
        "options": {"legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value", "percent"]},
            "pieType": "donut", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}}}

def tt(t, ds, q, field, x=0, w=12, h=8, sz="15", tf="@timestamp"):
    p = ny(h) if x == 0 else y - h
    return {"type": "table", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                "settings": {"size": sz, "order": "desc", "orderBy": "1", "min_doc_count": 1}}],
            "timeField": tf}]}

def multi_table(t, ds, q, fields, x=0, w=24, h=8, tf="@timestamp"):
    p = ny(h)
    aggs = [{"id": str(i+2), "type": "terms", "field": f,
            "settings": {"size": s, "order": "desc", "orderBy": "1", "min_doc_count": 1}}
           for i, (f, s) in enumerate(fields)]
    return {"type": "table", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": p},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": aggs, "timeField": tf}]}

def ts(t, ds, q, x=0, w=24, h=7, split=None, tf="@timestamp"):
    aggs = []
    if split:
        aggs.append({"id": "3", "type": "terms", "field": split,
            "settings": {"size": "10", "order": "desc", "orderBy": "1", "min_doc_count": 1}})
    aggs.append({"id": "2", "type": "date_histogram", "field": tf,
        "settings": {"interval": "auto", "min_doc_count": 0}})
    return {"type": "timeseries", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": ny(h)},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"},
            "custom": {"drawStyle": "line", "fillOpacity": 20, "lineInterpolation": "smooth",
                "lineWidth": 2, "showPoints": "never", "stacking": {"group": "A", "mode": "normal"}}}},
        "targets": [{"refId": "A", "query": q, "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": aggs, "timeField": tf}],
        "options": {"legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]},
            "tooltip": {"mode": "multi", "sort": "desc"}}}

def logs(t, ds, q, x=0, w=24, h=8):
    return {"type": "logs", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": ny(h)},
        "targets": [{"refId": "A", "query": q,
            "metrics": [{"id": "1", "type": "logs", "settings": {"limit": "50"}}],
            "bucketAggs": [], "timeField": "@timestamp"}]}

def geomap(t, ds, q, x=0, w=24, h=10):
    return {"type": "geomap", "title": t, "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": x, "y": ny(h)},
        "targets": [{"refId": "A", "query": q,
            "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "geohash_grid", "field": "source.geo.location",
                "settings": {"precision": "3"}}],
            "timeField": "@timestamp"}],
        "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
            "thresholds": {"steps": [{"color": "green", "value": None},
                {"color": "yellow", "value": 100}, {"color": "red", "value": 1000}]}}},
        "options": {
            "view": {"id": "zero", "lat": 30, "lon": 20, "zoom": 2},
            "basemap": {"type": "xyz", "name": "ESRI World Imagery",
                "config": {"attribution": "Esri, Maxar, Earthstar Geographics",
                    "url": "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"}},
            "tooltip": {"mode": "details"},
            "layers": [{"type": "markers", "name": "Attacks", "tooltip": True,
                "config": {
                    "showLegend": True,
                    "style": {
                        "color": {"field": "Count", "fixed": "yellow"},
                        "opacity": 0.8,
                        "size": {"field": "Count", "min": 4, "max": 15, "fixed": 5},
                        "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"},
                    }},
                "location": {"mode": "geohash", "geohash": "source.geo.location"},
            }]}}

P = []

# ═══════ GLOBAL OVERVIEW ═══════
P.append(row("Global Threat Overview"))
ny(4)
P.append(stat("SSH Attempts", HP, SV, 0, 4, color="#5865F2"))
P.append(stat("Successful Logins", HP, f"{SV} AND auth_success:true", 4, 4, color="#ED4245"))
P.append(stat("Unique IPs", HP, SV, 8, 4, mt="cardinality", f="src_ip", color="#FE8D2F"))
P.append(stat("Passwords Used", HP, SV, 12, 4, mt="cardinality", f="password", color="#FEE75C"))
P.append(stat("Honeypot Events", HP, CONTAINERS, 16, 4, color="#9b59b6"))
P.append(stat("Malware Analyzed", MA, "*", 20, 4, color="#57F287", tf="indexed_at"))

# Geo maps — T-Pot honeypots + sacrificial VM attackers (side by side)
P.append(geomap("Attacker Origins — T-Pot Honeypots", HP, f"{EXT} AND source.geo.location:* AND {CONTAINERS}", w=12))
y -= 10  # rewind y so next map shares the same row
P.append(geomap("Attacker Origins — Sacrificial VM", HP, f"observer.product:sacrificial-vm AND source.geo.location:*", x=12, w=12))

# Timeline — PAM auth (this data definitely exists)
P.append(ts("SSH Auth Timeline", HP, SV, split="auth_success", h=7))

# ═══════ SSH HONEYPOT ═══════
P.append(row("SSH Honeypot — Brute Force Analysis"))

# Successful logins — IP + password + reason (verified fields: src_ip, password, auth_reason)
P.append(multi_table("Successful Logins — IP / Password / Reason", HP,
    f"{SV} AND auth_success:true",
    [("src_ip", "25"), ("password", "3"), ("auth_reason", "3")]))

# Three column breakdown
P.append(tt("Top Attacker IPs", HP, SV, "src_ip", 0, 8))
P.append(tt("Usernames Tried", HP, SV, "username", 8, 8))
P.append(tt("Passwords Tried", HP, SV, "password", 16, 8))

# Donuts — auth_reason and auth_success (verified fields)
P.append(pie("Auth Outcomes", HP, SV, "auth_reason", 0, 12, 8))
P.append(pie("Success vs Fail", HP, SV, "auth_success", 12, 12, 8))

# ═══════ CREDENTIAL INTELLIGENCE ═══════
P.append(row("Credential Intelligence"))

# Trending passwords over time
P.append(ts("Trending Passwords", HP, SV, split="password", h=7))

# Password success rate — which passwords actually get in
P.append(multi_table("Password Success Rate", HP, SV,
    [("password", "25"), ("auth_success", "2")], w=12))

# Credential reuse — same password from multiple IPs (botnet indicator)
P.append(multi_table("Credential Reuse — Password × Source IP (successes only)", HP,
    f"{SV} AND auth_success:true",
    [("password", "20"), ("src_ip", "10")], w=12))

# Top username/password combos
P.append(multi_table("Top Username / Password Combos", HP, SV,
    [("username", "15"), ("password", "15")], w=12))

# Password popularity by hour of day
P.append(ts("Password Attempts by Hour", HP, SV, w=12, h=7))

# ═══════ ATTACKER INTEL ═══════
P.append(row("Attacker Intelligence"))

# Geo data from container events (source.geo.country_name has 39M events)
P.append(pie("Attacker Countries", HP, f"source.geo.country_name:* AND {EXT} AND {CONTAINERS}", "source.geo.country_name", 0, 12, 8))
P.append(pie("By Honeypot Type", HP, CONTAINERS, "container.name", 12, 12, 8))

# Attacker table with country (container events have geo)
P.append(multi_table("Attackers — IP / Country / Honeypot", HP,
    f"{EXT} AND {CONTAINERS} AND source.geo.country_name:*",
    [("src_ip", "20"), ("source.geo.country_name", "3"), ("container.name", "5")]))

# ═══════ POST-EXPLOITATION ═══════
P.append(row("Post-Exploitation — Auditd"))
ny(4)
# Verified auditd fields: event.action, process.executable, process.name, process.args
P.append(stat("Execve Events", HP, f"{AQ} AND event.action:execve", 0, 6, color="#ED4245"))
P.append(stat("Unique Binaries", HP, f"{AQ} AND event.action:execve", 6, 6, mt="cardinality", f="process.executable", color="#FE8D2F"))
P.append(stat("Auth Events", HP, f"{AQ} AND event.category:authentication", 12, 6, color="#FEE75C"))
P.append(stat("Network Events", HP, f"{AQ} AND event.action:sockaddr", 18, 6, color="#9b59b6"))

P.append(ts("Process Execution", HP, f"{AQ} AND event.action:execve", split="process.executable", h=7))

P.append(tt("Executables", HP, f"{AQ} AND event.action:execve", "process.executable", 0, 12))
P.append(pie("Event Types", HP, AQ, "event.action", 12, 12, 8))

# ═══════ MALWARE ANALYSIS ═══════
P.append(row("Malware Analysis Results"))
ny(4)
# Malware index uses indexed_at as timestamp
P.append(stat("Total", MA, "*", 0, 4, color="#5865F2", tf="indexed_at"))
P.append(stat("Critical", MA, "severity:critical", 4, 4, color="#ED4245", tf="indexed_at"))
P.append(stat("High", MA, "severity:high", 8, 4, color="#FE8D2F", tf="indexed_at"))
P.append(stat("ELF", MA, "is_elf:true", 12, 4, color="#57F287", tf="indexed_at"))
P.append(stat("PE", MA, "is_pe:true", 16, 4, color="#FEE75C", tf="indexed_at"))
P.append(stat("YARA Hits", MA, "yara_matches:*", 20, 4, color="#9b59b6", tf="indexed_at"))

P.append(pie("Classification", MA, "*", "classification", 0, 8, 8, tf="indexed_at"))
P.append(pie("Severity", MA, "*", "severity", 8, 8, 8, tf="indexed_at"))
P.append(pie("File Types", MA, "*", "mime_type", 16, 8, 8, tf="indexed_at"))

P.append(multi_table("Samples — Hash / Type / Classification / Severity", MA, "*",
    [("sha256", "20"), ("mime_type", "3"), ("classification", "3"), ("severity", "3")], tf="indexed_at"))

# ═══════ OTHER HONEYPOTS ═══════
P.append(row("Dionaea / Tanner / h0neytr4p"))
ny(4)
P.append(stat("Dionaea", HP, "container.name:dionaea", 0, 8, color="#57F287"))
P.append(stat("Tanner", HP, "container.name:tanner", 8, 8, color="#5865F2"))
P.append(stat("h0neytr4p", HP, "container.name:h0neytr4p", 16, 8, color="#FE8D2F"))

P.append(ts("Activity", HP, "container.name:dionaea OR container.name:tanner OR container.name:h0neytr4p", split="container.name", h=7))

# ═══════ LIVE FEED ═══════
P.append(row("Live Feed"))
P.append(logs("Recent SSH Auth Events", HP, SV, h=10))

# ═══════ DEPLOY ═══════
r = requests.post(f"{BASE}/api/dashboards/db", headers=H, json={
    "dashboard": {
        "title": "Honeypot Threat Overview", "uid": "tpot-attack-overview",
        "tags": ["honeypot", "cowrie", "sacrificial-vm", "malware"],
        "timezone": "browser", "refresh": "1m",
        "time": {"from": "now-7d", "to": "now"},
        "panels": P,
    }, "overwrite": True,
}, verify=False, timeout=30).json()

print(f"Status: {r.get('status','?')} v{r.get('version','?')} | {len(P)} panels")
for p in P:
    if p["type"] == "row": print(f"  {p['title']}")
