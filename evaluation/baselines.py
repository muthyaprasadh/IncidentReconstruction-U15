"""
Investigation Baseline Approaches for U-15 Incident Reconstruction.

BASELINE 1: Process evidence only.
BASELINE 2: Process + Registry evidence, same correlators as the proposed method (no network).
BASELINE 3: All evidence sources with conventional rule-based correlation (process, registry,
            Sysmon network, five-tuple), without graph connected-component reasoning.
PROPOSED METHOD: Provenance-aware evidence graph over the same rule-based relationships.
"""
from typing import List, Dict, Any, Set, Tuple, Optional
from database.models import NormalizedEvent, EventRelationship
from correlation.correlation_engine import CorrelationEngine
from correlation.process_correlation import event_process_guid
from evaluation.metrics import ForensicEvaluator
import networkx as nx


class BaselineRunner:
    @staticmethod
    def _find_suspect_pids(events: List[NormalizedEvent]) -> Set[int]:
        suspect_pids = set()
        for e in events:
            p_name = (e.process_name or "").lower()
            if p_name and p_name not in ["svchost.exe", "services.exe", "explorer.exe", "smss.exe", "csrss.exe"]:
                if e.pid is not None:
                    suspect_pids.add(e.pid)
            elif "incidentlab" in (e.file_path or "").lower() or "incidentlab" in (e.registry_key or "").lower():
                if e.pid is not None:
                    suspect_pids.add(e.pid)
        if not suspect_pids:
            suspect_pids = {e.pid for e in events if e.pid is not None}
        return suspect_pids

    @staticmethod
    def _chronology(events: List[NormalizedEvent], ids: Set[str]) -> List[str]:
        pred_events = [e for e in events if e.event_id in ids]
        return [e.event_id for e in sorted(pred_events, key=lambda x: x.timestamp or "")]

    @classmethod
    def run_method_1_process_only(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:
        """Method 1: Investigate using process evidence alone."""
        proc_events = [e for e in events if e.source == "process"]
        suspect_pids = cls._find_suspect_pids(proc_events)

        by_ppid: Dict[int, List[NormalizedEvent]] = {}
        for pe in proc_events:
            if pe.ppid is not None:
                by_ppid.setdefault(pe.ppid, []).append(pe)

        expanded_pids = set(suspect_pids)
        for spid in list(suspect_pids):
            for child in by_ppid.get(spid, []):
                if child.pid is not None:
                    expanded_pids.add(child.pid)

        predicted_events = [e for e in proc_events if e.pid in expanded_pids]
        predicted_event_ids = {e.event_id for e in predicted_events}

        relationships: List[Tuple[str, str, str]] = []
        by_pid = {e.pid: e for e in proc_events if e.pid is not None and e.event_type.upper() == "PROCESS_START"}
        for child in proc_events:
            if child.event_type.upper() == "PROCESS_START" and child.ppid in by_pid and child.event_id in predicted_event_ids:
                parent = by_pid[child.ppid]
                relationships.append((parent.event_id, child.event_id, "SPAWNED"))

        return predicted_event_ids, relationships, cls._chronology(proc_events, predicted_event_ids)

    @classmethod
    def run_baseline_1_process_only(cls, *args, **kwargs):
        """Backward-compatible alias for Method 1."""
        return cls.run_method_1_process_only(*args, **kwargs)

    @classmethod
    def run_method_2_network_only(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:
        """Method 2: Investigate using network evidence alone (no endpoint process or registry context)."""
        net_events = [e for e in events if e.source == "network" or e.event_type.upper() in ("NET_PACKET", "NET_CONNECT")]
        
        # Suspect network traffic: connections to non-loopback external or non-DNS traffic
        suspect_eids: Set[str] = set()
        for ne in net_events:
            dip = ne.dst_ip or ""
            sip = ne.src_ip or ""
            # Identify external or remote communications
            if dip and not dip.startswith("127.") and dip != "localhost":
                suspect_eids.add(ne.event_id)
            elif sip and not sip.startswith("127.") and sip != "localhost":
                suspect_eids.add(ne.event_id)

        if not suspect_eids:
            suspect_eids = {e.event_id for e in net_events}

        # Correlate network observations among themselves (Sysmon EID 3 to packet observations)
        sysmon_net = [e for e in net_events if (e.metadata or {}).get("sysmon_event_id") == 3]
        wire_net = [e for e in net_events if e not in sysmon_net]

        relationships: List[Tuple[str, str, str]] = []
        from correlation.network_correlation import NetworkCorrelator
        for sn in sysmon_net:
            for wn in wire_net:
                is_match, _ = NetworkCorrelator._matches_five_tuple(sn, wn)
                if is_match:
                    relationships.append((sn.event_id, wn.event_id, "OBSERVED_IN"))
                    suspect_eids.add(sn.event_id)
                    suspect_eids.add(wn.event_id)

        return suspect_eids, relationships, cls._chronology(net_events, suspect_eids)

    @classmethod
    def run_baseline_2_proc_and_reg(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:
        """Backward-compatible Baseline 2: Process + Registry."""
        filtered_events = [e for e in events if e.source in ["process", "registry"]]
        engine = CorrelationEngine(case_id=case_id, temporal_window=temporal_window)
        rels = engine.run(filtered_events, save_to_db=False)
        suspect_pids = cls._find_suspect_pids(filtered_events)

        predicted_event_ids = set()
        rel_tuples: List[Tuple[str, str, str]] = []
        for e in filtered_events:
            if e.pid in suspect_pids:
                predicted_event_ids.add(e.event_id)

        for r in rels:
            if r.source_event_id in predicted_event_ids or r.target_event_id in predicted_event_ids:
                rel_tuples.append((r.source_event_id, r.target_event_id, r.relationship_type))
                predicted_event_ids.add(r.source_event_id)
                predicted_event_ids.add(r.target_event_id)

        return predicted_event_ids, rel_tuples, cls._chronology(filtered_events, predicted_event_ids)

    @classmethod
    def run_method_3_rule_based(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0,
        correlation_options: Optional[Dict[str, bool]] = None,
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:
        """
        Method 3: Rule-Based Correlation.
        Conventional correlation on all sources (PID, timestamps, IP addresses, parent-child)
        without graph connected-component reasoning.
        """
        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=temporal_window,
            **(correlation_options or {})
        )
        rels = engine.run(events, save_to_db=False)
        suspect_pids = cls._find_suspect_pids(events)

        seed_event_ids = {
            e.event_id
            for e in events
            if e.source == "process" and e.pid in suspect_pids
        }
        predicted_event_ids = set(seed_event_ids)
        rel_tuples: List[Tuple[str, str, str]] = []

        for r in rels:
            touches_seed = (
                r.source_event_id in seed_event_ids or
                r.target_event_id in seed_event_ids
            )
            if touches_seed:
                rel_tuples.append((r.source_event_id, r.target_event_id, r.relationship_type))
                predicted_event_ids.add(r.source_event_id)
                predicted_event_ids.add(r.target_event_id)

        return predicted_event_ids, rel_tuples, cls._chronology(events, predicted_event_ids)

    @classmethod
    def run_baseline_3_all_no_graph(cls, *args, **kwargs):
        """Backward-compatible alias for Method 3."""
        return cls.run_method_3_rule_based(*args, **kwargs)

    @classmethod
    def run_method_4_proposed_graph(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        temporal_window: float = 5.0,
        correlation_options: Optional[Dict[str, bool]] = None,
    ) -> Tuple[Set[str], List[Tuple[str, str, str]], List[str]]:
        """
        Method 4: Proposed Cross-Artifact Graph Method.
        Uses ProcessGuid, process lifetime, Registry evidence, direction-aware network matching,
        timestamps, evidence provenance, and multi-hop graph component reconstruction.
        """
        engine = CorrelationEngine(
            case_id=case_id,
            temporal_window=temporal_window,
            **(correlation_options or {})
        )
        rels = engine.run(events, save_to_db=False)
        suspect_pids = cls._find_suspect_pids(events)

        G = nx.DiGraph()
        for r in rels:
            if r.confidence_score >= 0.70 or r.relationship_category in ["Directly observed", "Strongly supported"]:
                G.add_edge(r.source_event_id, r.target_event_id, rel=r)

        seed_eids = {e.event_id for e in events if e.pid in suspect_pids}

        # Method 4 does provenance-aware multi-hop reconstruction: it starts from
        # suspect process seeds and retains nodes/edges that participate in a
        # trusted causal path (at most seven hops), rather than expanding an
        # entire relationship component like a conventional graph.
        incident_event_ids: Set[str] = set()
        for seed in seed_eids:
            incident_event_ids.add(seed)
            if G.has_node(seed):
                for target in G.nodes:
                    if target == seed:
                        continue
                    try:
                        path = nx.shortest_path(G, seed, target)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
                    if len(path) - 1 <= 7:
                        incident_event_ids.update(path)

        rel_tuples: List[Tuple[str, str, str]] = []
        for u, v, data in G.edges(data=True):
            if u in incident_event_ids and v in incident_event_ids:
                rel_obj = data["rel"]
                rel_tuples.append((rel_obj.source_event_id, rel_obj.target_event_id, rel_obj.relationship_type))

        return incident_event_ids, rel_tuples, cls._chronology(events, incident_event_ids)

    @classmethod
    def run_proposed_method(cls, *args, **kwargs):
        """Backward-compatible alias for Method 4."""
        return cls.run_method_4_proposed_graph(*args, **kwargs)

    @classmethod
    def evaluate_all_methods(
        cls,
        events: List[NormalizedEvent],
        case_id: str,
        ground_truth_incident_ids: Set[str],
        ground_truth_relationships: List[Tuple[str, str, str]],
        ground_truth_chronology: List[str],
        temporal_window: float = 5.0,
    ) -> List[Dict[str, Any]]:
        all_eids = {e.event_id for e in events}
        runners = [
            ("Method 1: Process-Only", cls.run_method_1_process_only),
            ("Method 2: Network-Only", cls.run_method_2_network_only),
            ("Method 3: Rule-Based Correlation", cls.run_method_3_rule_based),
            ("Method 4: Proposed Cross-Artifact Graph", cls.run_method_4_proposed_graph),
        ]
        rows = []
        for name, fn in runners:
            eids, rels, chrono = fn(events, case_id, temporal_window=temporal_window)
            event_m = ForensicEvaluator.calculate_classification_metrics(eids, ground_truth_incident_ids, all_eids)
            rel_m = ForensicEvaluator.calculate_relationship_metrics(rels, ground_truth_relationships)
            order = ForensicEvaluator.calculate_timeline_ordering_accuracy(chrono, ground_truth_chronology)
            
            # Coverage: fraction of incident events recovered
            gt_count = len(ground_truth_incident_ids)
            coverage = (event_m["tp"] / gt_count) if gt_count > 0 else 1.0

            rows.append({
                "method": name,
                "event_coverage": round(coverage, 4),
                **event_m,
                **rel_m,
                "timeline_accuracy": order,
            })
        return rows
