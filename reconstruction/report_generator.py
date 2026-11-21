from pathlib import Path

from typing import Dict, Any, List, Optional

from datetime import datetime, timezone

from xml.sax.saxutils import escape

import re

import csv

from reportlab.lib.pagesizes import letter

from reportlab.lib import colors

from reportlab.lib.units import inch

from reportlab.platypus import (

    SimpleDocTemplate,

    Paragraph,

    Spacer,

    Table,

    LongTable,

    TableStyle,

    HRFlowable

)

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from config.settings import REPORTS_DIR, logger

class ForensicReportGenerator:

    @staticmethod

    def _safe(value: Any, fallback: str = "Unavailable") -> str:

        if value is None:

            return fallback

        text = str(value).strip()

        if not text:

            return fallback

        return escape(text)

    @staticmethod

    def _paragraph(value: Any, style, fallback: str = "Unavailable") -> Paragraph:

        return Paragraph(

            ForensicReportGenerator._safe(value, fallback),

            style

        )

    @staticmethod
    def _load_benchmark_metrics() -> List[Dict[str, Any]]:
        csv_path = Path(__file__).resolve().parents[1] / "reports" / "evaluation_metrics.csv"

        if not csv_path.exists():
            logger.warning("Benchmark metrics CSV not found: %s", csv_path)
            return []

        try:
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as file:
                return list(csv.DictReader(file))
        except (OSError, csv.Error) as error:
            logger.exception("Failed to load benchmark metrics: %s", error)
            return []

    @staticmethod

    def _timestamp(entry: Dict[str, Any]) -> str:

        value = entry.get("display_time")

        if not value:

            return "Unavailable"

        value = str(value).strip()

        if not value:

            return "Unavailable"

        return escape(value)

    @staticmethod

    def _description(value: Any) -> str:

        if value is None:

            return "No activity description available."

        text = str(value).strip()

        if not text:

            return "No activity description available."

        text = re.sub(

            r"Process\s+''",

            "Process 'Unknown'",

            text,

            flags=re.IGNORECASE

        )

        text = re.sub(
            r'''Process\s+["']{2}''',
            'Process "Unknown"',
            text,
            flags=re.IGNORECASE
        )

        return escape(text)

    @staticmethod

    def _table_style(header=True):

        commands = [

            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#D1D5DB")),

            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("LEFTPADDING", (0, 0), (-1, -1), 5),

            ("RIGHTPADDING", (0, 0), (-1, -1), 5),

            ("TOPPADDING", (0, 0), (-1, -1), 5),

            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),

        ]

        if header:

            commands.append(

                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A"))

            )

        return TableStyle(commands)

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

        case_info = case_info or {}

        evidence_files = evidence_files or []

        timeline_entries = timeline_entries or []

        relationships = relationships or []

        evaluation_data = evaluation_data or []

        graph_stats = graph_stats or {}

        narrative_data = narrative_data or {}

        case_id = str(case_info.get("case_id") or "CASE-UNKNOWN")

        safe_case_id = re.sub(

            r"[^A-Za-z0-9_.-]",

            "_",

            case_id

        )

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        file_path = REPORTS_DIR / f"Forensic_Report_{safe_case_id}.pdf"

        doc = SimpleDocTemplate(

            str(file_path),

            pagesize=letter,

            rightMargin=36,

            leftMargin=36,

            topMargin=42,

            bottomMargin=42,

            title=f"Forensic Investigation Report - {case_id}",

            author="U-15 Incident Reconstruction Research Project",

            subject="Cross-Artifact Incident Reconstruction"

        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(

            "DocTitle",

            parent=styles["Normal"],

            fontName="Helvetica-Bold",

            fontSize=19,

            leading=24,

            textColor=colors.HexColor("#1E3A8A"),

            spaceAfter=8

        )

        subtitle_style = ParagraphStyle(

            "DocSubtitle",

            parent=styles["Normal"],

            fontName="Helvetica-Bold",

            fontSize=10,

            leading=14,

            textColor=colors.HexColor("#4B5563"),

            spaceAfter=12

        )

        h1_style = ParagraphStyle(

            "Header1",

            parent=styles["Heading1"],

            fontName="Helvetica-Bold",

            fontSize=13,

            leading=17,

            textColor=colors.HexColor("#1F2937"),

            spaceBefore=14,

            spaceAfter=7,

            keepWithNext=True

        )

        body_style = ParagraphStyle(

            "Body",

            parent=styles["Normal"],

            fontName="Helvetica",

            fontSize=8.5,

            leading=12,

            textColor=colors.HexColor("#374151"),

            spaceAfter=5

        )

        small_style = ParagraphStyle(

            "Small",

            parent=body_style,

            fontSize=7.5,

            leading=10

        )

        table_header_style = ParagraphStyle(

            "TableHeader",

            parent=styles["Normal"],

            fontName="Helvetica-Bold",

            fontSize=7.5,

            leading=9,

            textColor=colors.white

        )

        table_cell_style = ParagraphStyle(

            "TableCell",

            parent=styles["Normal"],

            fontName="Helvetica",

            fontSize=7.5,

            leading=9,

            textColor=colors.HexColor("#1F2937"),

            wordWrap="CJK"

        )

        elements = []

        def heading(number, title):

            elements.append(

                Paragraph(f"{number}. {title}", h1_style)

            )

        def header_row(names):

            return [

                Paragraph(f"<b>{escape(name)}</b>", table_header_style)

                for name in names

            ]

        elements.append(

            Paragraph(

                "DIGITAL FORENSIC INVESTIGATION REPORT",

                title_style

            )

        )

        elements.append(

            Paragraph(

                "<b>Research Project U-15:</b> "

                "Cross-Artifact Incident Reconstruction from "

                "Process, Registry &amp; Network Evidence",

                subtitle_style

            )

        )

        elements.append(

            HRFlowable(

                width="100%",

                thickness=1.5,

                color=colors.HexColor("#1E3A8A"),

                spaceAfter=12

            )

        )

        elements.append(

            Paragraph(

                "<b>Research output:</b> This report presents "

                "evidence and reconstructed relationships available "

                "to the application at generation time. It is not "

                "a certification of forensic completeness or "

                "court admissibility.",

                body_style

            )

        )

        heading(1, "Executive Case Information")

        generated_time = datetime.now(timezone.utc).strftime(

            "%Y-%m-%d %H:%M UTC"

        )

        case_data = [

            [

                Paragraph("<b>Case ID:</b>", table_cell_style),

                ForensicReportGenerator._paragraph(

                    case_info.get("case_id"), table_cell_style

                ),

                Paragraph("<b>Collection Date:</b>", table_cell_style),

                ForensicReportGenerator._paragraph(

                    case_info.get("collection_date"), table_cell_style

                )

            ],

            [

                Paragraph("<b>Investigation Name:</b>", table_cell_style),

                ForensicReportGenerator._paragraph(

                    case_info.get("name"), table_cell_style

                ),

                Paragraph("<b>Report Generated:</b>", table_cell_style),

                Paragraph(generated_time, table_cell_style)

            ],

            [

                Paragraph("<b>Description:</b>", table_cell_style),

                ForensicReportGenerator._paragraph(

                    case_info.get("description"), table_cell_style

                ),

                Paragraph("<b>Status:</b>", table_cell_style),

                ForensicReportGenerator._paragraph(

                    case_info.get("status"), table_cell_style

                )

            ]

        ]

        case_table = Table(

            case_data,

            colWidths=[

                1.15 * inch,

                2.35 * inch,

                1.15 * inch,

                2.35 * inch

            ]

        )

        case_table.setStyle(

            TableStyle([

                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),

                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#D1D5DB")),

                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),

                ("VALIGN", (0, 0), (-1, -1), "TOP"),

                ("LEFTPADDING", (0, 0), (-1, -1), 5),

                ("RIGHTPADDING", (0, 0), (-1, -1), 5),

                ("TOPPADDING", (0, 0), (-1, -1), 5),

                ("BOTTOMPADDING", (0, 0), (-1, -1), 5)

            ])

        )

        elements.append(case_table)

        heading(2, "Forensic Evidence Sources Ingested")

        evidence_rows = [

            header_row([

                "Source",

                "Filename",

                "Size (Bytes)",

                "Records",

                "Integrity Status"

            ])

        ]

        for item in evidence_files:

            evidence_rows.append([

                ForensicReportGenerator._paragraph(

                    str(item.get("source_type", "Unknown")).upper(),

                    table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    item.get("file_name"), table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    item.get("file_size", 0), table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    item.get("record_count", 0), table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    item.get("status"), table_cell_style

                )

            ])

        if not evidence_files:

            evidence_rows.append([

                ForensicReportGenerator._paragraph(

                    "No evidence files registered.", table_cell_style

                ),

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style)

            ])

        evidence_table = LongTable(

            evidence_rows,

            colWidths=[

                1.05 * inch,

                2.65 * inch,

                1.0 * inch,

                0.8 * inch,

                1.5 * inch

            ],

            repeatRows=1

        )

        evidence_table.setStyle(

            ForensicReportGenerator._table_style()

        )

        elements.append(evidence_table)

        heading(3, "Scientific Investigation Methodology")

        method_desc = (

            "This investigation utilizes a <b>cross-artifact "

            "provenance-aware evidence graph</b> approach. "

            "It examines endpoint process activity, Registry-related "

            "operations and network packet evidence. Process Monitor "

            "telemetry can provide process, file and Registry operation "

            "records. Sysmon process creation and network connection "

            "events provide additional endpoint context. Wireshark "

            "captures provide packet-level observations. "

            "Network connections are attributed to endpoint processes "

            "only when supported by endpoint socket telemetry and "

            "matching on the complete five-tuple: source IP, destination "

            "IP, source port, destination port and protocol. "

            "Process lifetime intervals are considered when evaluating "

            "process identity and possible PID reuse. Registry access "

            "operations are not automatically interpreted as Registry "

            "value modifications."

        )

        elements.append(

            Paragraph(method_desc, body_style)

        )

        heading(4, "Reconstructed Incident Timeline & Provenance")

        timeline_limit = 20

        selected_timeline = timeline_entries[:timeline_limit]

        elements.append(

            Paragraph(

                f"The following table contains up to {timeline_limit} "

                f"timeline entries supplied to the report generator. "

                f"Total supplied entries: <b>{len(timeline_entries):,}</b>. "

                "This is a selected excerpt, not necessarily the complete "

                "case timeline. Missing or unreliable timestamps are "

                "reported as Unavailable and are not inferred.",

                body_style

            )

        )

        timeline_rows = [

            header_row([

                "Timestamp",

                "Source",

                "Activity Description",

                "Provenance Reference"

            ])

        ]

        for entry in selected_timeline:

            timeline_rows.append([

                Paragraph(

                    ForensicReportGenerator._timestamp(entry),

                    table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    str(entry.get("source") or "Unknown").upper(),

                    table_cell_style

                ),

                Paragraph(

                    ForensicReportGenerator._description(

                        entry.get("description")

                    ),

                    table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    entry.get("evidence_provenance"),

                    table_cell_style

                )

            ])

        if not selected_timeline:

            timeline_rows.append([

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style),

                Paragraph("No timeline events supplied.", table_cell_style),

                Paragraph("-", table_cell_style)

            ])

        timeline_table = LongTable(

            timeline_rows,

            colWidths=[

                1.05 * inch,

                0.8 * inch,

                3.7 * inch,

                1.45 * inch

            ],

            repeatRows=1

        )

        timeline_table.setStyle(

            ForensicReportGenerator._table_style()

        )

        elements.append(timeline_table)

        heading(5, "Evidence Graph & Correlation Reasoning")

        if graph_stats:

            stats_text = (

                f"Total Graph Entities: "

                f"<b>{graph_stats.get('node_count', 'Unavailable')}</b>"

                f" | Directed Causal Edges: "

                f"<b>{graph_stats.get('edge_count', 'Unavailable')}</b>"

                f" | Independent Clusters: "

                f"<b>{graph_stats.get('connected_clusters', 'Unavailable')}</b>"

            )

            elements.append(

                Paragraph(stats_text, body_style)

            )

        else:

            elements.append(

                Paragraph(

                    "Graph statistics were not supplied.",

                    body_style

                )

            )

        relationship_limit = 10

        selected_relationships = relationships[:relationship_limit]

        elements.append(

            Paragraph(

                f"Showing up to {relationship_limit} relationship records "

                f"from {len(relationships):,} supplied records. "

                "This is a selected excerpt.",

                body_style

            )

        )

        relationship_rows = [

            header_row([

                "Type",

                "Category",

                "Confidence",

                "Forensic Explanation"

            ])

        ]

        for relationship in selected_relationships:

            confidence = relationship.get("confidence_score")

            try:

                confidence_text = f"{float(confidence):.2f}"

            except (TypeError, ValueError):

                confidence_text = "Unavailable"

            relationship_rows.append([

                ForensicReportGenerator._paragraph(

                    relationship.get("relationship_type"),

                    table_cell_style

                ),

                ForensicReportGenerator._paragraph(

                    relationship.get("relationship_category"),

                    table_cell_style

                ),

                Paragraph(confidence_text, table_cell_style),

                ForensicReportGenerator._paragraph(

                    relationship.get("explanation"),

                    table_cell_style

                )

            ])

        if not selected_relationships:

            relationship_rows.append([

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style),

                Paragraph("-", table_cell_style),

                Paragraph("No relationships supplied.", table_cell_style)

            ])

        relationship_table = LongTable(

            relationship_rows,

            colWidths=[

                1.15 * inch,

                1.2 * inch,

                0.8 * inch,

                3.85 * inch

            ],

            repeatRows=1

        )

        relationship_table.setStyle(

            ForensicReportGenerator._table_style()

        )

        elements.append(relationship_table)

        heading(6, "Research Evaluation: Multi-Source vs Isolated Baselines")

        if evaluation_data:

            evaluation_rows = [

                header_row([

                    "Methodology",

                    "Precision",

                    "Recall",

                    "F1-Score",

                    "FPR"

                ])

            ]

            for evaluation in evaluation_data:

                def metric(key):

                    try:

                        return f"{float(evaluation.get(key)):.4f}"

                    except (TypeError, ValueError):

                        return "Unavailable"

                evaluation_rows.append([

                    ForensicReportGenerator._paragraph(

                        evaluation.get("method"),

                        table_cell_style

                    ),

                    Paragraph(metric("precision"), table_cell_style),

                    Paragraph(metric("recall"), table_cell_style),

                    Paragraph(metric("f1_score"), table_cell_style),

                    Paragraph(metric("false_positive_rate"), table_cell_style)

                ])

            evaluation_table = LongTable(

                evaluation_rows,

                colWidths=[

                    3.0 * inch,

                    1.0 * inch,

                    1.0 * inch,

                    1.0 * inch,

                    1.0 * inch

                ],

                repeatRows=1

            )

            evaluation_table.setStyle(

                ForensicReportGenerator._table_style()

            )

            elements.append(evaluation_table)

        else:

            elements.append(

                Paragraph(

                    "Evaluation metrics were not supplied for this report. "

                    "No performance comparison is presented.",

                    body_style

                )

            )

        heading(7, "Research Benchmark Evaluation Results")

        benchmark_data = ForensicReportGenerator._load_benchmark_metrics()

        if benchmark_data:
            elements.append(
                Paragraph(
                    "The following results are read from the project benchmark CSV. "
                    "They are scenario-level mean metrics and are separate from the "
                    "case-specific evaluation above and from the real Windows experiment. "
                    "Values are reported as supplied; they are not recalculated here.",
                    body_style
                )
            )

            split_order = ["All Scenarios", "Development", "Held-Out Test"]
            metric_columns = [
                ("mean_precision", "Precision"),
                ("mean_recall", "Recall"),
                ("mean_f1_score", "F1"),
                ("mean_false_positive_rate", "FPR"),
                ("mean_event_coverage", "Event Cov."),
                ("mean_relationship_f1", "Rel. F1"),
                ("mean_timeline_accuracy", "Timeline Acc.")
            ]

            for split in split_order:
                split_rows = [
                    row for row in benchmark_data
                    if row.get("dataset_split") == split
                ]

                if not split_rows:
                    continue

                elements.append(Spacer(1, 6))
                elements.append(
                    Paragraph(
                        f"<b>{escape(split)}</b> "
                        f"({escape(str(split_rows[0].get('scenarios_evaluated', 'Unavailable')))} scenarios)",
                        body_style
                    )
                )

                benchmark_rows = [
                    header_row(["Investigation Method"] + [label for _, label in metric_columns])
                ]

                for row in split_rows:
                    values = [
                        ForensicReportGenerator._paragraph(
                            row.get("investigation_method"), table_cell_style
                        )
                    ]

                    for key, _ in metric_columns:
                        try:
                            value = f"{float(row.get(key)):.4f}"
                        except (TypeError, ValueError):
                            value = "Unavailable"
                        values.append(Paragraph(value, table_cell_style))

                    benchmark_rows.append(values)

                benchmark_table = LongTable(
                    benchmark_rows,
                    colWidths=[
                        1.75 * inch,
                        0.62 * inch,
                        0.62 * inch,
                        0.55 * inch,
                        0.55 * inch,
                        0.68 * inch,
                        0.58 * inch,
                        0.70 * inch
                    ],
                    repeatRows=1
                )
                benchmark_table.setStyle(
                    ForensicReportGenerator._table_style()
                )
                elements.append(benchmark_table)

            elements.append(Spacer(1, 6))
            elements.append(
                Paragraph(
                    "<b>Interpretation:</b> The proposed cross-artifact graph has a higher "
                    "mean F1-score than the rule-based correlation method in each reported "
                    "split. Its false-positive rate is not lower: it is higher in All "
                    "Scenarios and Development, and equal in the Held-Out Test split. "
                    "The Held-Out Test contains only three scenarios, so this result "
                    "should be interpreted cautiously and is not conclusive evidence "
                    "of broad generalization.",
                    body_style
                )
            )
        else:
            elements.append(
                Paragraph(
                    "Benchmark metrics CSV was not available. No benchmark comparison "
                    "is presented.",
                    body_style
                )
            )

        heading(8, "Research Limitations & Disclaimers")


        disclaimer_text = (

            "<b>Forensic Integrity:</b> The reconstructed chronology "

            "and graph relationships represent the telemetry and "

            "correlation results available to the application. "

            "A missing timestamp must not be interpreted as proof "

            "that an event did not occur. "

            "Process and network attribution depends on the availability "

            "and quality of endpoint telemetry. Temporal proximity alone "

            "does not establish process ownership of a network packet. "

            "Registry access operations do not independently prove that "

            "a Registry value was changed. "

            "The selected timeline and relationship tables are excerpts "

            "and may not represent every event or graph edge in the case. "

            "Evaluation results apply only to their documented datasets "

            "and experimental conditions. "

            "<b>This research report is not a certified forensic "

            "examination, legal opinion or guarantee of court "

            "admissibility.</b>"

        )

        elements.append(

            Paragraph(disclaimer_text, body_style)

        )

        elements.append(Spacer(1, 12))

        elements.append(

            HRFlowable(

                width="100%",

                thickness=0.7,

                color=colors.HexColor("#D1D5DB"),

                spaceAfter=6

            )

        )

        elements.append(

            Paragraph(

                "End of Report | U-15 Cross-Artifact Incident Reconstruction",

                small_style

            )

        )

        doc.build(elements)

        logger.info(

            "PDF investigation report generated successfully at: %s",

            file_path

        )

        return file_path
