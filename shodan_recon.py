#!/usr/bin/env python3
"""
Shodan Infrastructure Recon — Index and visualize country-level infrastructure.

Pulls infrastructure data from Shodan API, indexes in Elasticsearch,
and provides a live Grafana dashboard showing exposed services,
vulnerabilities, organizations, and changes over time.

Usage:
    python3 shodan_recon.py --country IR --query "country:IR"         # Full Iran scan
    python3 shodan_recon.py --country IR --query "country:IR port:22" # SSH only
    python3 shodan_recon.py --country IR --query "country:IR vuln:CVE-2021-44228"  # Log4j
    python3 shodan_recon.py --country IR --query "country:IR product:SCADA"        # ICS/SCADA
    python3 shodan_recon.py --facets --country IR                     # Quick facet summary
    python3 shodan_recon.py --monitor --country IR                    # Continuous monitoring
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import requests
import shodan

ES_URL = "http://localhost:9200"
LOG_FILE = "/home/legs/shodan_recon.log"

# Interesting queries for infrastructure research
RESEARCH_QUERIES = {
    "scada_ics": 'country:{country} (product:SCADA OR product:Modbus OR product:"Siemens" OR port:502 OR port:102 OR port:44818 OR product:"Allen-Bradley" OR product:"Schneider Electric")',
    "power_grid": 'country:{country} (product:"ABB" OR product:"GE" OR tag:"ics" OR port:20000 OR product:"Honeywell")',
    "water_systems": 'country:{country} (product:"SCADA" OR tag:"ics") port:502',
    "cameras": 'country:{country} (product:"Hikvision" OR product:"Dahua" OR product:"IP Camera" OR product:"webcam" OR product:"Axis")',
    "databases_exposed": 'country:{country} (port:27017 OR port:9200 OR port:5432 OR port:3306 OR port:6379) -authentication',
    "rdp_exposed": 'country:{country} port:3389',
    "smb_exposed": 'country:{country} port:445',
    "telnet_exposed": 'country:{country} port:23',
    "vpn_servers": 'country:{country} (port:1194 OR port:1723 OR product:"OpenVPN" OR product:"PPTP")',
    "medical": 'country:{country} (product:"DICOM" OR port:104 OR port:11112)',
    "printers": 'country:{country} (port:9100 OR product:"printer")',
    "mikrotik": 'country:{country} product:"MikroTik"',
    "critical_vulns": 'country:{country} (vuln:CVE-2021-44228 OR vuln:CVE-2021-26855 OR vuln:CVE-2017-0144 OR vuln:CVE-2019-19781 OR vuln:CVE-2021-34527)',
    "default_creds": 'country:{country} (http.title:"login" OR http.title:"admin" OR http.title:"dashboard") (default OR admin OR password)',
    "nuclear": 'country:{country} (org:"Atomic Energy" OR org:"nuclear")',
    "government": 'country:{country} (org:"government" OR hostname:".gov.ir" OR hostname:".ir")',
    "telecom": 'country:{country} (org:"Telecommunication" OR org:"telecom")',
    "universities": 'country:{country} (org:"university" OR org:"University" OR org:"institute")',
}


def setup_logging():
    logger = logging.getLogger("shodan_recon")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=5)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


def ensure_index(index_name):
    """Create ES index for Shodan data."""
    resp = requests.get(f"{ES_URL}/{index_name}", timeout=5)
    if resp.status_code == 200:
        return

    requests.put(f"{ES_URL}/{index_name}", json={
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "product": {"type": "keyword"},
                "version": {"type": "keyword"},
                "os": {"type": "keyword"},
                "org": {"type": "keyword"},
                "asn": {"type": "keyword"},
                "isp": {"type": "keyword"},
                "hostnames": {"type": "keyword"},
                "domains": {"type": "keyword"},
                "city": {"type": "keyword"},
                "country": {"type": "keyword"},
                "country_code": {"type": "keyword"},
                "location": {"type": "geo_point"},
                "vulns": {"type": "keyword"},
                "cpes": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "transport": {"type": "keyword"},
                "banner": {"type": "text", "index": False},
                "http_title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "http_server": {"type": "keyword"},
                "http_status": {"type": "integer"},
                "ssl_cipher": {"type": "keyword"},
                "ssl_version": {"type": "keyword"},
                "ssl_cert_subject": {"type": "text"},
                "ssl_cert_issuer": {"type": "text"},
                "ssl_cert_expired": {"type": "boolean"},
                "query_tag": {"type": "keyword"},
                "scan_date": {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    }, timeout=10)


def index_host(index_name, host, query_tag="general"):
    """Index a single Shodan host result into ES."""
    ip = host.get("ip_str", "")
    location = host.get("location", {})

    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "port": host.get("port"),
        "protocol": host.get("transport", "tcp"),
        "product": host.get("product", ""),
        "version": host.get("version", ""),
        "os": host.get("os", ""),
        "org": host.get("org", ""),
        "asn": host.get("asn", ""),
        "isp": host.get("isp", ""),
        "hostnames": host.get("hostnames", []),
        "domains": host.get("domains", []),
        "city": location.get("city", ""),
        "country": location.get("country_name", ""),
        "country_code": location.get("country_code", ""),
        "vulns": list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else host.get("vulns", []),
        "cpes": host.get("cpes", []),
        "tags": host.get("tags", []),
        "transport": host.get("transport", ""),
        "banner": (host.get("data", "") or "")[:500],
        "query_tag": query_tag,
        "scan_date": host.get("timestamp", ""),
    }

    # HTTP data
    http = host.get("http", {})
    if http:
        doc["http_title"] = http.get("title", "")
        doc["http_server"] = http.get("server", "")
        doc["http_status"] = http.get("status")

    # SSL data
    ssl = host.get("ssl", {})
    if ssl:
        cipher = ssl.get("cipher", {})
        doc["ssl_cipher"] = cipher.get("name", "")
        doc["ssl_version"] = cipher.get("version", "")
        cert = ssl.get("cert", {})
        if cert:
            subject = cert.get("subject", {})
            doc["ssl_cert_subject"] = " ".join(f"{k}={v}" for k, v in subject.items()) if isinstance(subject, dict) else str(subject)
            issuer = cert.get("issuer", {})
            doc["ssl_cert_issuer"] = " ".join(f"{k}={v}" for k, v in issuer.items()) if isinstance(issuer, dict) else str(issuer)
            doc["ssl_cert_expired"] = cert.get("expired", False)

    # Geo point
    lat = location.get("latitude")
    lon = location.get("longitude")
    if lat and lon:
        doc["location"] = {"lat": lat, "lon": lon}

    doc_id = f"{ip}-{host.get('port', 0)}-{host.get('transport', 'tcp')}"

    try:
        requests.put(f"{ES_URL}/{index_name}/_doc/{doc_id}", json=doc, timeout=5)
    except Exception:
        pass


def run_query(api, query, index_name, query_tag, logger, max_results=1000):
    """Run a Shodan search and index results."""
    logger.info("Query: %s (max %d results)", query[:80], max_results)

    try:
        total = api.count(query)["total"]
        logger.info("Total matches: %d", total)
    except shodan.APIError as e:
        logger.error("Count failed: %s", e)
        return 0

    indexed = 0
    page = 1

    while indexed < max_results:
        try:
            results = api.search(query, page=page)
            matches = results.get("matches", [])
            if not matches:
                break

            for host in matches:
                index_host(index_name, host, query_tag)
                indexed += 1
                if indexed >= max_results:
                    break

            logger.info("  Page %d: %d results (total indexed: %d)", page, len(matches), indexed)
            page += 1
            time.sleep(1)  # Rate limit

        except shodan.APIError as e:
            if "rate limit" in str(e).lower():
                logger.warning("Rate limited — waiting 60s")
                time.sleep(60)
                continue
            logger.error("Search error: %s", e)
            break

    logger.info("Indexed %d results for '%s'", indexed, query_tag)
    return indexed


def run_facets(api, country, logger):
    """Quick faceted summary without using query credits."""
    facet_list = ["port", "org", "product", "os", "vuln", "city", "asn"]

    try:
        result = api.count(f"country:{country}", facets=[(f, 20) for f in facet_list])
        logger.info("Total hosts in %s: %d", country, result["total"])
        print(f"\n{'='*60}")
        print(f"  {country} Infrastructure Summary — {result['total']:,} hosts")
        print(f"{'='*60}")

        for facet_name in facet_list:
            items = result.get("facets", {}).get(facet_name, [])
            if items:
                print(f"\n  --- {facet_name.upper()} ---")
                for item in items:
                    print(f"    {str(item['value']):45s} {item['count']:>10,}")

    except shodan.APIError as e:
        logger.error("Facets failed: %s", e)


def run_research(api, country, index_name, logger, max_per_query=100):
    """Run all research queries for a country."""
    total = 0

    for tag, query_template in RESEARCH_QUERIES.items():
        query = query_template.format(country=country)
        logger.info("Research query: %s", tag)
        count = run_query(api, query, index_name, tag, logger, max_results=max_per_query)
        total += count
        time.sleep(2)

    logger.info("Total indexed across all research queries: %d", total)
    return total


def main():
    parser = argparse.ArgumentParser(description="Shodan Infrastructure Recon")
    parser.add_argument("--country", default="IR", help="Country code (default: IR)")
    parser.add_argument("--query", help="Custom Shodan query")
    parser.add_argument("--index", default="shodan-recon", help="ES index name")
    parser.add_argument("--max-results", type=int, default=500, help="Max results per query")
    parser.add_argument("--facets", action="store_true", help="Quick faceted summary only")
    parser.add_argument("--research", action="store_true", help="Run all research queries")
    parser.add_argument("--monitor", action="store_true", help="Continuous monitoring (daily rescan)")
    parser.add_argument("--query-tag", default="custom", help="Tag for custom queries")
    args = parser.parse_args()

    logger = setup_logging()
    api_key = os.environ.get("SHODAN_API_KEY", "JpTObcaJoZFT5HutMdNvczGfjHNNdLyB")
    api = shodan.Shodan(api_key)

    ensure_index(args.index)

    if args.facets:
        run_facets(api, args.country, logger)
        return

    if args.research:
        run_research(api, args.country, args.index, logger, max_per_query=args.max_results)
        return

    if args.monitor:
        logger.info("Starting continuous monitoring for %s", args.country)
        running = True

        def handle_signal(signum, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        while running:
            run_research(api, args.country, args.index, logger, max_per_query=args.max_results)
            logger.info("Next scan in 24 hours")
            for _ in range(86400):
                if not running:
                    break
                time.sleep(1)
        return

    if args.query:
        run_query(api, args.query, args.index, args.query_tag, logger, max_results=args.max_results)
    else:
        # Default: general country scan
        run_query(api, f"country:{args.country}", args.index, "general", logger, max_results=args.max_results)


if __name__ == "__main__":
    main()
