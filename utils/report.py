import os
from datetime import datetime
from typing import Dict, Any

import csv
from fpdf import FPDF
import pandas as pd

BASE_REPORTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(BASE_REPORTS, exist_ok=True)


def generate_pdf_report(data: Dict[str, Any], options: Dict[str, Any] | None = None) -> str:
    options = options or {}
    include_summary = options.get("include_summary", True)
    include_alerts = options.get("include_alerts", True)
    include_counts = options.get("include_counts", True)
    include_meta = options.get("include_meta", True)
    summary = data.get("summary", {})
    alerts = data.get("alerts", [])

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "DDoS Analysis Report", ln=True)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Generated: {datetime.utcnow().isoformat()}Z", ln=True)
    pdf.ln(4)

    if include_summary:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, "Summary", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 6, f"Total Packets: {summary.get('total_packets', 0)}", ln=True)
        pdf.cell(0, 6, f"Duration (s): {round(summary.get('duration_seconds', 0), 2)}", ln=True)
        pr = summary.get("protocol_ratio", {})
        pdf.cell(0, 6, f"ICMP/TCP/UDP: {pr.get('ICMP',0)}/{pr.get('TCP',0)}/{pr.get('UDP',0)}", ln=True)
        pdf.cell(0, 6, f"Unique Sources: {summary.get('unique_sources', 0)}", ln=True)
        pdf.cell(0, 6, f"Unique Destinations: {summary.get('unique_dests', 0)}", ln=True)
        pdf.ln(4)

    if include_alerts:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, "Alerts", ln=True)
        pdf.set_font("Arial", size=12)
        if not alerts:
            pdf.cell(0, 6, "No alerts generated.", ln=True)
        else:
            for a in alerts[:30]:
                pdf.multi_cell(0, 6, f"[{a.get('severity','')}] {a.get('message','')}")
                pdf.ln(1)

    out = os.path.join(BASE_REPORTS, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")
    pdf.output(out)
    return out


def generate_csv_report(data: Dict[str, Any]) -> str:
    out = os.path.join(BASE_REPORTS, f"packets_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")
    packets = data.get("packets", [])
    if not packets:
        with open(out, "w", newline="", encoding="utf-8") as f:
            f.write("")
        return out
    fieldnames = [
        "time", "time_iso", "src", "dst", "protocol", "length", "flags", "info", "src_port", "dst_port", "icmp_type"
    ]
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for p in packets:
            writer.writerow({k: p.get(k) for k in fieldnames})
    return out


def generate_xlsx_report(data: Dict[str, Any]) -> str:
    out = os.path.join(BASE_REPORTS, f"packets_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx")
    packets = data.get("packets", [])
    df = pd.DataFrame(packets)
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="packets")
        # add summary sheet
        summary = data.get("summary", {})
        s_df = pd.DataFrame([{**summary, **summary.get("protocol_ratio", {})}])
        s_df.to_excel(writer, index=False, sheet_name="summary")
    return out


