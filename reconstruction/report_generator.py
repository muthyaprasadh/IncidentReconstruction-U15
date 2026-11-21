"""
PDF and Multi-Format Investigation Report Generator for U-15 Incident Reconstruction.
Generates comprehensive research-grade forensic PDF reports using ReportLab.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import json

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from config.settings import REPORTS_DIR, logger

class ForensicReportGenerator:
    @staticmethod
    def generate_pdf_report(
        case_info: Dict[str, Any],
        evidence_files: List[Dict[str, Any]],
        timeline_entries: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        narrative_data: Dict[str, Any],
        evaluation_data: Optional[List[Dict[str, Any]]] = None,
        graph_stats: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Creates a research investigation PDF report. This output is not a court-admissible exhibit.
        """
        case_id = case_info.get("case_id", "CASE-UNKNOWN")
        file_path = REPORTS_DIR / f"Forensic_Report_{case_id}.pdf"

        doc = SimpleDocTemplate(
            str(file_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom dark/enterprise palette styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#1E3A8A'),
            spaceAfter=8
        )

        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#4B5563'),
            spaceAfter=14
        )

        h1_style = ParagraphStyle(
            'Header1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1F2937'),
            spaceBefore=14,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#374151')
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.white
        )

        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1F2937')
        )

        elements = []

        # Header Title
        elements.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(Paragraph(
            f"<b>Research Project U-15:</b> Cross-Artifact Incident Reconstruction from Process, Registry & Network Evidence",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#1E3A8A'), spaceAfter=12))

        # 1. Case Metadata Table
        elements.append(Paragraph("1. Executive Case Information", h1_style))
        case_data = [
            [Paragraph("<b>Case ID:</b>", body_style), Paragraph(case_info.get("case_id", ""), table_cell_style),
             Paragraph("<b>Collection Date:</b>", body_style), Paragraph(case_info.get("collection_date", ""), table_cell_style)],
            [Paragraph("<b>Investigation Name:</b>", body_style), Paragraph(case_info.get("name", ""), table_cell_style),
             Paragraph("<b>Report Generated:</b>", body_style), Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), table_cell_style)],
            [Paragraph("<b>Description:</b>", body_style), Paragraph(case_info.get("description", "N/A"), table_cell_style),
             Paragraph("<b>Status:</b>", body_style), Paragraph(case_info.get("status", "Active"), table_cell_style)]
        ]
        t_case = Table(case_data, colWidths=[1.3*inch, 2.3*inch, 1.4*inch, 2.3*inch])
        t_case.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F3F4F6')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#D1D5DB')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_case)
        elements.append(Spacer(1, 10))

        # 2. Evidence Files
        elements.append(Paragraph("2. Forensic Evidence Sources Ingested", h1_style))
        ev_headers = [Paragraph("<b>Source</b>", table_header_style), Paragraph("<b>Filename</b>", table_header_style),
                      Paragraph("<b>Size (Bytes)</b>", table_header_style), Paragraph("<b>Records</b>", table_header_style),
                      Paragraph("<b>Integrity Status</b>", table_header_style)]
        ev_rows = [ev_headers]
        for f in evidence_files:
            ev_rows.append([
                Paragraph(f.get("source_type", "").upper(), table_cell_style),
                Paragraph(f.get("file_name", ""), table_cell_style),
                Paragraph(str(f.get("file_size", 0)), table_cell_style),
                Paragraph(str(f.get("record_count", 0)), table_cell_style),
                Paragraph(f.get("status", "Verified"), table_cell_style)
            ])
        if len(ev_rows) == 1:
            ev_rows.append([Paragraph("No evidence files registered.", table_cell_style), Paragraph("-", table_cell_style), Paragraph("-", table_cell_style), Paragraph("-", table_cell_style), Paragraph("-", table_cell_style)])
        
        t_ev = Table(ev_rows, colWidths=[1.1*inch, 2.8*inch, 1.1*inch, 1.0*inch, 1.3*inch])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E3A8A')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#D1D5DB')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_ev)
        elements.append(Spacer(1, 10))

        # 3. Investigation Methodology
        elements.append(Paragraph("3. Scientific Investigation Methodology", h1_style))
        method_desc = (
            "This investigation utilized a <b>cross-artifact provenance-aware evidence graph</b> approach. "
            "Rather than relying on isolated endpoint or network artifacts, the platform correlated Sysinternals "
            "Process Monitor telemetry (process lifecycle, parent-child PPIDs, endpoint network sockets) with "
            "Windows Registry state mutations and Wireshark wire packet captures. "
            "Crucially, network connections were attributed to endpoint processes only when supported by "
            "endpoint socket telemetry matching on the exact five-tuple (src_ip, dst_ip, src_port, dst_port, protocol). "
            "Process lifetime intervals were validated to prevent false PID reuse attribution."
        )
        elements.append(Paragraph(method_desc, body_style))
        elements.append(Spacer(1, 10))

        # 4. Reconstructed Timeline (Top Key Events)
        elements.append(Paragraph("4. Reconstructed Incident Timeline & Provenance", h1_style))
        t_headers = [Paragraph("<b>Timestamp (UTC)</b>", table_header_style), Paragraph("<b>Source</b>", table_header_style),
                     Paragraph("<b>Activity Description</b>", table_header_style), Paragraph("<b>Provenance Reference</b>", table_header_style)]
        time_rows = [t_headers]
        for entry in timeline_entries[:20]:  # Up to 20 key events
            time_rows.append([
                Paragraph(entry.get("display_time", "")[11:], table_cell_style),
                Paragraph(entry.get("source", "").upper(), table_cell_style),
                Paragraph(entry.get("description", ""), table_cell_style),
                Paragraph(entry.get("evidence_provenance", ""), table_cell_style)
            ])
        if len(time_rows) == 1:
            time_rows.append([Paragraph("-", table_cell_style), Paragraph("-", table_cell_style), Paragraph("No timeline events.", table_cell_style), Paragraph("-", table_cell_style)])
        
        t_time = Table(time_rows, colWidths=[1.2*inch, 0.9*inch, 3.7*inch, 1.5*inch])
        t_time.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E3A8A')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#D1D5DB')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(t_time)
        elements.append(Spacer(1, 10))

        # 5. Cross-Artifact Correlation & Evidence Graph
        elements.append(Paragraph("5. Evidence Graph & Correlation Reasoning", h1_style))
        if graph_stats:
            stats_p = f"Total Graph Entities: <b>{graph_stats.get('node_count', 0)}</b> | Directed Causal Edges: <b>{graph_stats.get('edge_count', 0)}</b> | Independent Clusters: <b>{graph_stats.get('connected_clusters', 0)}</b>"
            elements.append(Paragraph(stats_p, body_style))
            elements.append(Spacer(1, 4))

        rel_headers = [Paragraph("<b>Type</b>", table_header_style), Paragraph("<b>Category</b>", table_header_style),
                       Paragraph("<b>Confidence</b>", table_header_style), Paragraph("<b>Forensic Explanation</b>", table_header_style)]
        rel_rows = [rel_headers]
        for r in relationships[:10]:
            rel_rows.append([
                Paragraph(r.get("relationship_type", ""), table_cell_style),
                Paragraph(r.get("relationship_category", ""), table_cell_style),
                Paragraph(f"{r.get('confidence_score', 0):.2f}", table_cell_style),
                Paragraph(r.get("explanation", ""), table_cell_style)
            ])
        if len(rel_rows) == 1:
            rel_rows.append([Paragraph("-", table_cell_style), Paragraph("-", table_cell_style), Paragraph("-", table_cell_style), Paragraph("No relationships correlated.", table_cell_style)])
        
        t_rel = Table(rel_rows, colWidths=[1.3*inch, 1.3*inch, 0.9*inch, 3.8*inch])
        t_rel.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E3A8A')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#D1D5DB')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(t_rel)
        elements.append(Spacer(1, 10))

        # 6. Evaluation vs Baselines Table
        if evaluation_data:
            elements.append(Paragraph("6. Research Evaluation: Multi-Source vs Isolated Baselines", h1_style))
            eval_headers = [Paragraph("<b>Methodology</b>", table_header_style), Paragraph("<b>Precision</b>", table_header_style),
                            Paragraph("<b>Recall</b>", table_header_style), Paragraph("<b>F1-Score</b>", table_header_style),
                            Paragraph("<b>FPR</b>", table_header_style)]
            eval_rows = [eval_headers]
            for ed in evaluation_data:
                eval_rows.append([
                    Paragraph(ed.get("method", ""), table_cell_style),
                    Paragraph(f"{ed.get('precision', 0):.4f}", table_cell_style),
                    Paragraph(f"{ed.get('recall', 0):.4f}", table_cell_style),
                    Paragraph(f"{ed.get('f1_score', 0):.4f}", table_cell_style),
                    Paragraph(f"{ed.get('false_positive_rate', 0):.4f}", table_cell_style),
                ])
            t_eval = Table(eval_rows, colWidths=[3.1*inch, 1.0*inch, 1.0*inch, 1.1*inch, 1.1*inch])
            t_eval.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E3A8A')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#D1D5DB')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(t_eval)
            elements.append(Spacer(1, 10))

        # 7. Limitations & Forensic Disclaimer
        elements.append(Paragraph("7. Research Limitations & Disclaimers", h1_style))
        disclaimer_text = (
            "<b>Forensic Integrity Disclaimer:</b> All reconstructed chronologies and graph relationships represent empirical "
            "telemetry and rule-grounded provenance. Single-source isolation (Baseline 1 & 2) suffers from systematic missing-evidence "
            "blind spots, while unconstrained temporal proximity (Baseline 3) induces false-positive socket misattributions. "
            "Proposed provenance graphs mitigate both limitations when endpoint socket telemetry is present."
        )
        elements.append(Paragraph(disclaimer_text, body_style))

        doc.build(elements)
        logger.info("PDF investigation report generated successfully at: %s", file_path)
        return file_path
