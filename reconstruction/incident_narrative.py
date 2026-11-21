"""
Incident Narrative Generator for U-15 Incident Reconstruction.
Transforms cross-artifact evidence graph and reconstructed timeline into an explainable,
chronological incident story adhering to forensic reporting standards.
"""
from typing import List, Dict, Any

class IncidentNarrativeGenerator:
    def __init__(self, timeline_entries: List[Any], relationships: List[Any]):
        def _to_d(x):
            if hasattr(x, "to_dict"):
                return x.to_dict()
            if isinstance(x, dict):
                return x
            try:
                return dict(x)
            except Exception:
                return x.__dict__

        self.timeline_entries = [_to_d(t) for t in timeline_entries]
        self.relationships = [_to_d(r) for r in relationships]

    def generate_narrative(self) -> Dict[str, Any]:
        """
        Produces both a concise chronological story and a structured executive forensic summary.
        """
        if not self.timeline_entries:
            return {
                "chronological_story": "No forensic events have been loaded or correlated for this case.",
                "story_lines": [],
                "phases_summary": {},
                "correlated_findings": [],
                "forensic_disclaimer": "No events analyzed."
            }

        story_lines = []
        phase_counts = {
            "Process Execution": 0,
            "File Activity": 0,
            "Registry Activity": 0,
            "Network Activity": 0
        }

        for entry in self.timeline_entries:
            t_str = entry["display_time"].split(" ")[-1] if " " in entry["display_time"] else entry["display_time"]
            desc = entry["description"]
            src = entry["source"]

            # Classify phase
            if src == "process":
                if entry["event_type"].startswith("FILE_"):
                    phase_counts["File Activity"] += 1
                else:
                    phase_counts["Process Execution"] += 1
            elif src == "registry":
                phase_counts["Registry Activity"] += 1
            elif src == "network":
                phase_counts["Network Activity"] += 1

            # Build line
            line = f"{t_str} - {desc}"
            
            # If the entry has strong cross-artifact links, append explanation
            strong_links = [l for l in entry.get("related_links", []) if l.get("category") in ["Directly observed", "Strongly supported"]]
            if strong_links:
                first_link = strong_links[0]
                line += f"  ↳ [{first_link['category']} link: {first_link['explanation']}]"
            story_lines.append(line)

        # Formulate analytical findings
        findings = []
        for rel in self.relationships:
            if rel.get("confidence_score", 0) >= 0.8:
                findings.append({
                    "type": rel.get("relationship_type"),
                    "category": rel.get("relationship_category"),
                    "confidence": rel.get("confidence_score"),
                    "explanation": rel.get("explanation"),
                    "method": rel.get("correlation_method")
                })

        disclaimer = (
            "FORENSIC OBJECTIVITY DISCLAIMER: This reconstruction represents empirical telemetry and rule-grounded "
            "temporal/provenance associations. No activity is classified as intrinsically malicious without external threat "
            "intelligence or established organizational security policy violations."
        )

        return {
            "chronological_story": "\n\n".join(story_lines),
            "story_lines": story_lines,
            "phases_summary": phase_counts,
            "correlated_findings": findings[:15],
            "forensic_disclaimer": disclaimer
        }
