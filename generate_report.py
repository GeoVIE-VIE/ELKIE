#!/usr/bin/env python3
"""
Malware Analysis Report Generator — Professional PDF reports

Generates a comprehensive threat analysis PDF from sample_analyzer results
stored in Elasticsearch. Suitable for portfolio, sharing, or incident response.

Usage:
    python3 generate_report.py <sha256>               # generate report for a specific sample
    python3 generate_report.py --latest                # generate report for the most recent sample
    python3 generate_report.py --all                   # generate reports for all samples
"""

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem,
)

ES_URL = "http://localhost:9200"
RESULT_INDEX = "malware-analysis"
REPORT_DIR = Path("/home/legs/reports")

# Colors
HEADER_BG = colors.HexColor("#1a1a2e")
HEADER_FG = colors.white
CRITICAL_COLOR = colors.HexColor("#ED4245")
HIGH_COLOR = colors.HexColor("#FE8D2F")
MEDIUM_COLOR = colors.HexColor("#FEE75C")
LOW_COLOR = colors.HexColor("#57F287")
ACCENT = colors.HexColor("#5865F2")
LIGHT_BG = colors.HexColor("#f5f5f5")

SEVERITY_COLORS = {
    "critical": CRITICAL_COLOR,
    "high": HIGH_COLOR,
    "medium": MEDIUM_COLOR,
    "low": LOW_COLOR,
}


def get_sample(sha256: str) -> dict:
    resp = requests.get(f"{ES_URL}/{RESULT_INDEX}/_doc/{sha256}", timeout=10)
    if resp.status_code == 200 and resp.json().get("found"):
        return resp.json()["_source"]
    return {}


def get_latest_sample() -> dict:
    resp = requests.post(f"{ES_URL}/{RESULT_INDEX}/_search", json={
        "size": 1, "sort": [{"indexed_at": "desc"}],
    }, timeout=10)
    hits = resp.json().get("hits", {}).get("hits", [])
    if hits:
        return hits[0]["_source"]
    return {}


def get_all_samples() -> list:
    resp = requests.post(f"{ES_URL}/{RESULT_INDEX}/_search", json={
        "size": 100, "sort": [{"indexed_at": "desc"}],
    }, timeout=10)
    return [h["_source"] for h in resp.json().get("hits", {}).get("hits", [])]


def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=24, textColor=HEADER_BG, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading1"],
        fontSize=14, textColor=HEADER_BG, spaceBefore=16, spaceAfter=8,
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "SubHeader", parent=styles["Heading2"],
        fontSize=11, textColor=ACCENT, spaceBefore=10, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "ReportBody", parent=styles["Normal"],
        fontSize=9, leading=13, alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        "CodeBlock", parent=styles["Code"],
        fontSize=7, leading=9, backColor=LIGHT_BG,
        borderWidth=0.5, borderColor=colors.grey, borderPadding=6,
    ))
    styles.add(ParagraphStyle(
        "SmallText", parent=styles["Normal"],
        fontSize=7, textColor=colors.grey,
    ))
    styles.add(ParagraphStyle(
        "SeverityBadge", parent=styles["Normal"],
        fontSize=12, alignment=TA_CENTER,
    ))
    return styles


def make_table(data, col_widths=None, header=True):
    """Create a styled table."""
    style_cmds = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header and data:
        style_cmds.extend([
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), HEADER_FG),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
        # Alternate row colors
        for i in range(1, len(data)):
            if i % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), LIGHT_BG))

    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle(style_cmds))
    return t


def truncate(text, max_len=80):
    if not text:
        return ""
    text = str(text)
    return text[:max_len] + "..." if len(text) > max_len else text


def generate_report(sample: dict, output_path: Path, styles):
    """Generate a PDF report for a single sample."""
    sha256 = sample.get("sha256", "unknown")
    classification = sample.get("classification", "unknown")
    severity = sample.get("severity", "medium")
    file_type = sample.get("file_type", "unknown")
    file_size = sample.get("file_size", 0)
    analyzed_at = sample.get("analyzed_at", "")
    source = sample.get("source", {})

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    elements = []

    # --- Title ---
    elements.append(Paragraph("MALWARE ANALYSIS REPORT", styles["ReportTitle"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    elements.append(Spacer(1, 12))

    # --- Executive Summary ---
    sev_color = SEVERITY_COLORS.get(severity, MEDIUM_COLOR)
    size_str = f"{file_size / 1024:.0f} KB" if file_size < 1048576 else f"{file_size / 1048576:.1f} MB"

    summary_data = [
        ["SHA256", sha256],
        ["MD5", sample.get("md5", "")],
        ["File Type", truncate(file_type, 60)],
        ["File Size", size_str],
        ["Classification", classification.upper()],
        ["Severity", severity.upper()],
        ["Analyzed", analyzed_at[:19] if analyzed_at else ""],
        ["Source Honeypot", source.get("honeypot", "unknown")],
        ["Attacker IP", source.get("src_ip", "N/A")],
        ["Country", source.get("country", "N/A")],
    ]

    elements.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    t = make_table([["Field", "Value"]] + summary_data, col_widths=[1.5 * inch, 5 * inch])
    elements.append(t)
    elements.append(Spacer(1, 12))

    # ssdeep
    if sample.get("ssdeep"):
        elements.append(Paragraph(f"<b>Fuzzy Hash (ssdeep):</b> <font size=7>{sample['ssdeep']}</font>", styles["ReportBody"]))
        elements.append(Spacer(1, 6))

    # --- LLM Threat Assessment ---
    llm = sample.get("llm_summary", "")
    if llm:
        elements.append(Paragraph("2. Threat Assessment (AI Analysis)", styles["SectionHeader"]))
        # Wrap long text
        for para in llm.split("\n\n"):
            para = para.strip()
            if para:
                # Escape XML-sensitive chars for reportlab
                para = para.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Paragraph(para, styles["ReportBody"]))
                elements.append(Spacer(1, 6))
        elements.append(Spacer(1, 6))

    # --- Threat Hypothesis ---
    hypothesis = sample.get("threat_hypothesis", "")
    if hypothesis:
        elements.append(Paragraph("2b. Threat Hypothesis", styles["SectionHeader"]))
        hypothesis = hypothesis.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(hypothesis, styles["ReportBody"]))
        elements.append(Spacer(1, 6))

    # --- MITRE ATT&CK ---
    mitre = sample.get("mitre_attack", [])
    if mitre:
        elements.append(Paragraph("2c. MITRE ATT&amp;CK Techniques", styles["SectionHeader"]))
        mitre_data = [["Technique"]]
        for t in mitre[:15]:
            t_escaped = str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            mitre_data.append([t_escaped])
        elements.append(make_table(mitre_data, col_widths=[6.5 * inch]))
        elements.append(Spacer(1, 6))

    # --- Warrants Investigation ---
    warrants = sample.get("warrants_investigation", [])
    if warrants and isinstance(warrants, list):
        elements.append(Paragraph("2d. Warrants Further Investigation", styles["SectionHeader"]))
        for w in warrants[:10]:
            w_escaped = str(w).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            elements.append(Paragraph(f"\u2022 {w_escaped}", styles["ReportBody"]))
        elements.append(Spacer(1, 6))

    # --- Deep Analysis (Ghidra MCP) ---
    deep = sample.get("deep_analysis", "")
    if deep:
        mode = sample.get("deep_analysis_mode", "batch")
        score = sample.get("deep_analysis_score", 0)
        cost = sample.get("deep_analysis_cost", 0)
        funcs = sample.get("deep_analysis_functions_analyzed", 0)
        mode_label = "Ghidra MCP Interactive" if mode == "ghidra_mcp_interactive" else "Ghidra Batch"
        elements.append(Paragraph(f"2e. Deep Code Analysis ({mode_label}, score={score}, ${cost:.2f})", styles["SectionHeader"]))
        for para in deep.split("\n\n"):
            para = para.strip()
            if not para:
                continue
            para = para.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            # Detect code blocks (lines starting with spaces/tabs or ```)
            if para.startswith("```") or para.startswith("    ") or para.startswith("\t"):
                para = para.replace("```", "").strip()
                elements.append(Paragraph(para, styles["CodeBlock"]))
            else:
                elements.append(Paragraph(para, styles["ReportBody"]))
            elements.append(Spacer(1, 4))
        elements.append(Spacer(1, 6))

    # --- YARA Matches ---
    yara = sample.get("yara_matches", [])
    elements.append(Paragraph("3. Detection Results", styles["SectionHeader"]))

    if yara:
        elements.append(Paragraph("<b>YARA Rule Matches:</b>", styles["SubHeader"]))
        yara_data = [["Rule Name"]] + [[y] for y in yara]
        elements.append(make_table(yara_data, col_widths=[6.5 * inch]))
    else:
        elements.append(Paragraph("No YARA rule matches.", styles["ReportBody"]))
    elements.append(Spacer(1, 8))

    # VT results
    vt = sample.get("virustotal", {})
    if vt:
        elements.append(Paragraph("<b>VirusTotal:</b>", styles["SubHeader"]))
        if vt.get("found"):
            vt_data = [
                ["Detection Ratio", vt.get("detection_ratio", "?")],
                ["Suggested Label", vt.get("suggested_label", "N/A")],
                ["Reputation", str(vt.get("reputation", "N/A"))],
                ["Tags", ", ".join(vt.get("tags", [])[:5])],
            ]
            elements.append(make_table([["Field", "Value"]] + vt_data, col_widths=[2 * inch, 4.5 * inch]))
        else:
            elements.append(Paragraph("Not found in VirusTotal (novel sample).", styles["ReportBody"]))
    elements.append(Spacer(1, 8))

    # --- capa Capabilities ---
    capa = sample.get("capa_capabilities", [])
    if capa:
        elements.append(Paragraph("4. Capabilities (MITRE ATT&CK)", styles["SectionHeader"]))
        capa_data = [["Capability", "Namespace"]]
        for c in capa[:25]:
            capa_data.append([truncate(c.get("name", ""), 50), truncate(c.get("namespace", ""), 40)])
        elements.append(make_table(capa_data, col_widths=[3.5 * inch, 3 * inch]))
        elements.append(Spacer(1, 8))

    # --- Ghidra ---
    ghidra = sample.get("ghidra")
    if ghidra and isinstance(ghidra, dict):
        elements.append(Paragraph("5. Binary Analysis (Ghidra)", styles["SectionHeader"]))

        ghidra_info = [
            ["Total Functions", str(ghidra.get("num_functions", 0))],
            ["Executable Format", ghidra.get("executable_format", "?")],
            ["Language", ghidra.get("language", "?")],
            ["Image Base", ghidra.get("image_base", "?")],
        ]
        elements.append(make_table([["Field", "Value"]] + ghidra_info, col_widths=[2 * inch, 4.5 * inch]))
        elements.append(Spacer(1, 6))

        suspicious = ghidra.get("suspicious_apis", [])
        if suspicious:
            elements.append(Paragraph("<b>Suspicious API Calls:</b>", styles["SubHeader"]))
            api_data = [["API Name"]] + [[a] for a in suspicious]
            elements.append(make_table(api_data, col_widths=[6.5 * inch]))
            elements.append(Spacer(1, 6))

        funcs = ghidra.get("functions", [])[:15]
        if funcs:
            elements.append(Paragraph("<b>Top Functions (by size):</b>", styles["SubHeader"]))
            func_data = [["Name", "Address", "Size (bytes)"]]
            for f in funcs:
                func_data.append([truncate(f["name"], 30), f["address"], str(f["size"])])
            elements.append(make_table(func_data, col_widths=[3 * inch, 2 * inch, 1.5 * inch]))
            elements.append(Spacer(1, 6))

        sections = ghidra.get("sections", [])
        if sections:
            elements.append(Paragraph("<b>Memory Sections:</b>", styles["SubHeader"]))
            sec_data = [["Name", "Permissions", "Size"]]
            for s in sections:
                sec_data.append([s["name"], s["permissions"], str(s["size"])])
            elements.append(make_table(sec_data, col_widths=[2.5 * inch, 1.5 * inch, 2.5 * inch]))

    # --- Dynamic Analysis ---
    dyn = sample.get("dynamic_analysis", {})
    if dyn:
        section_num = 6 if ghidra else 5
        elements.append(Paragraph(f"{section_num}. Dynamic Analysis (Sandbox Detonation)", styles["SectionHeader"]))
        elements.append(Paragraph(
            f"Detonation duration: {dyn.get('detonation_duration', '?')} seconds | "
            f"PCAP size: {dyn.get('pcap_size', 0)} bytes | "
            f"Audit log: {dyn.get('audit_log_size', 0)} bytes",
            styles["ReportBody"]
        ))
        elements.append(Spacer(1, 6))

        dns = dyn.get("dns_queries", [])
        if dns:
            elements.append(Paragraph("<b>DNS Queries:</b>", styles["SubHeader"]))
            dns_data = [["Domain"]] + [[d] for d in dns[:20]]
            elements.append(make_table(dns_data, col_widths=[6.5 * inch]))
            elements.append(Spacer(1, 6))

        conns = dyn.get("outbound_connections", [])
        if conns:
            elements.append(Paragraph("<b>Outbound Connections:</b>", styles["SubHeader"]))
            conn_data = [["Destination IP", "Port"]]
            for c in conns[:20]:
                conn_data.append([c["ip"], c["port"]])
            elements.append(make_table(conn_data, col_widths=[4 * inch, 2.5 * inch]))
            elements.append(Spacer(1, 6))

        new_files = dyn.get("new_files", [])
        if new_files:
            elements.append(Paragraph("<b>Files Created:</b>", styles["SubHeader"]))
            file_data = [["File Path"]] + [[truncate(f, 70)] for f in new_files[:15]]
            elements.append(make_table(file_data, col_widths=[6.5 * inch]))
            elements.append(Spacer(1, 6))

        # Filesystem diff
        fs_changes = dyn.get("filesystem_changes", {})
        if fs_changes and isinstance(fs_changes, dict):
            fs_new = fs_changes.get("new", [])
            fs_mod = fs_changes.get("modified", [])
            fs_del = fs_changes.get("deleted", [])
            if fs_new or fs_mod or fs_del:
                elements.append(Paragraph("<b>Filesystem Changes:</b>", styles["SubHeader"]))
                fs_data = [["Type", "Path"]]
                for f in fs_new[:10]:
                    fs_data.append(["NEW", truncate(f, 65)])
                for f in fs_mod[:10]:
                    fs_data.append(["MODIFIED", truncate(f, 65)])
                for f in fs_del[:5]:
                    fs_data.append(["DELETED", truncate(f, 65)])
                elements.append(make_table(fs_data, col_widths=[1.2 * inch, 5.3 * inch]))
                elements.append(Spacer(1, 6))

        # Strace summary
        strace = dyn.get("strace") or {}
        net_ops = strace.get("network_operations", [])
        if net_ops:
            elements.append(Paragraph("<b>Strace Network Operations:</b>", styles["SubHeader"]))
            net_data = [["PID", "Syscall", "Details"]]
            for op in net_ops[:15]:
                net_data.append([op.get("pid", "?"), op.get("syscall", "?"), truncate(op.get("args", op.get("path", "")), 50)])
            elements.append(make_table(net_data, col_widths=[0.8 * inch, 1.5 * inch, 4.2 * inch]))
            elements.append(Spacer(1, 6))

        proc_tree = dyn.get("process_tree", [])
        if proc_tree:
            elements.append(Paragraph("<b>Process Tree:</b>", styles["SubHeader"]))
            proc_data = [["PID", "PPID", "Command"]]
            for p in proc_tree[:15]:
                proc_data.append([str(p.get("pid", "?")), str(p.get("ppid", "?")), truncate(p.get("cmd", "?"), 55)])
            elements.append(make_table(proc_data, col_widths=[0.8 * inch, 0.8 * inch, 4.9 * inch]))

    # --- IOCs ---
    section_num = (7 if ghidra else 6) if dyn else (6 if ghidra else 5)
    elements.append(Paragraph(f"{section_num}. Indicators of Compromise", styles["SectionHeader"]))

    ioc_data = [["Type", "Value"]]
    ioc_data.append(["SHA256", sha256])
    if sample.get("md5"):
        ioc_data.append(["MD5", sample["md5"]])
    if source.get("src_ip"):
        ioc_data.append(["Attacker IP", source["src_ip"]])

    for s in sample.get("interesting_strings", [])[:15]:
        if "http" in s.lower():
            ioc_data.append(["URL", truncate(s, 70)])
        elif any(c.isdigit() for c in s) and "." in s and len(s) < 20:
            ioc_data.append(["IP", s])

    if dyn:
        for d in dyn.get("dns_queries", [])[:10]:
            ioc_data.append(["Domain (sandbox)", d])
        for c in dyn.get("outbound_connections", [])[:10]:
            ioc_data.append(["C2 Connection", f"{c['ip']}:{c['port']}"])

    elements.append(make_table(ioc_data, col_widths=[1.5 * inch, 5 * inch]))
    elements.append(Spacer(1, 8))

    # --- Similar Samples ---
    similar = sample.get("similar_samples", [])
    if similar:
        section_num += 1
        elements.append(Paragraph(f"{section_num}. Related Samples (Fuzzy Hash Similarity)", styles["SectionHeader"]))
        sim_data = [["SHA256", "Similarity", "Classification"]]
        for s in similar[:10]:
            sim_data.append([s["sha256"][:32] + "...", f"{s['similarity']}%", s.get("classification", "?")])
        elements.append(make_table(sim_data, col_widths=[3.5 * inch, 1.5 * inch, 1.5 * inch]))
        elements.append(Spacer(1, 8))

    # --- Generated YARA Rule ---
    gen_yara = sample.get("generated_yara_rule", "")
    if gen_yara:
        section_num += 1
        elements.append(Paragraph(f"{section_num}. Auto-Generated Detection Rule", styles["SectionHeader"]))
        yara_escaped = gen_yara.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(yara_escaped, styles["CodeBlock"]))
        elements.append(Spacer(1, 8))

    # --- Interesting Strings ---
    strings = sample.get("interesting_strings", [])
    if strings:
        section_num += 1
        elements.append(Paragraph(f"{section_num}. Notable Strings", styles["SectionHeader"]))
        str_data = [["String"]]
        for s in strings[:30]:
            s_escaped = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            str_data.append([truncate(s_escaped, 90)])
        elements.append(make_table(str_data, col_widths=[6.5 * inch]))

    # --- Footer ---
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Report generated by ELKIE SOC — Automated Malware Analysis Pipeline | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["SmallText"]
    ))
    elements.append(Paragraph(
        f"Classification: {classification.upper()} | Severity: {severity.upper()} | "
        f"Analysis version: {sample.get('analysis_version', '?')}",
        styles["SmallText"]
    ))

    doc.build(elements)
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Malware Analysis Report Generator")
    parser.add_argument("sha256", nargs="?", help="SHA256 of sample to report on")
    parser.add_argument("--latest", action="store_true", help="Report on most recent sample")
    parser.add_argument("--all", action="store_true", help="Generate reports for all samples")
    parser.add_argument("--output-dir", default=str(REPORT_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    styles = build_styles()

    if args.all:
        samples = get_all_samples()
        print(f"Generating reports for {len(samples)} samples...")
        for sample in samples:
            sha = sample.get("sha256", "unknown")
            out = output_dir / f"{sha[:16]}_report.pdf"
            generate_report(sample, out, styles)
            cls = sample.get("classification", "?")
            print(f"  {out.name} — {cls}")
        print(f"Done. Reports in {output_dir}")

    elif args.latest:
        sample = get_latest_sample()
        if not sample:
            print("No samples found in ES")
            sys.exit(1)
        sha = sample.get("sha256", "unknown")
        out = output_dir / f"{sha[:16]}_report.pdf"
        generate_report(sample, out, styles)
        print(f"Report: {out}")

    elif args.sha256:
        sample = get_sample(args.sha256)
        if not sample:
            print(f"Sample {args.sha256} not found")
            sys.exit(1)
        out = output_dir / f"{args.sha256[:16]}_report.pdf"
        generate_report(sample, out, styles)
        print(f"Report: {out}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
