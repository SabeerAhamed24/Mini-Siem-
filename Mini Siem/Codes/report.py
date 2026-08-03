from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
from db import get_report_data

def generate_pdf_report(output_path="siem_report.pdf", hours=24):
    severity_counts, top_sources, recent_alerts = get_report_data(hours=hours)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"Mini-SIEM Report (Last {hours} hours)")
    y -= 25

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 30

    # Severity counts
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Severity Summary")
    y -= 18
    c.setFont("Helvetica", 10)
    if not severity_counts:
        c.drawString(60, y, "No logs found.")
        y -= 15
    else:
        for sev, cnt in severity_counts:
            c.drawString(60, y, f"{sev}: {cnt}")
            y -= 14

    y -= 10

    # Top sources
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Top Sources")
    y -= 18
    c.setFont("Helvetica", 10)
    if not top_sources:
        c.drawString(60, y, "No sources found.")
        y -= 15
    else:
        for src, cnt in top_sources:
            c.drawString(60, y, f"{src}: {cnt}")
            y -= 14

    y -= 10

# Recent alerts
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Recent Alerts (non-INFO)")
    y -= 18
    c.setFont("Helvetica", 9)

    if not recent_alerts:
        c.drawString(60, y, "No alerts found.")
        y -= 15
    else:
        for ts, src, lt, sev, msg in recent_alerts:
            line = f"[{ts}] {src} | {lt} | {sev} | {msg[:90]}"
            c.drawString(50, y, line)
            y -= 12
            if y < 70:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 9)

    c.save()
    return output_path


if __name__ == "__main__":
    path = generate_pdf_report("siem_report.pdf", hours=24)
    print(f"Report generated: {path}")
