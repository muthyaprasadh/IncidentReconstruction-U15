# U-15 Codebase Audit

## Status and scope

**Phase:** 1 — Repository audit only  
**Outcome:** Audit and technical-debt documentation added; no application source, tests, SQLite database, ground truth, manifests, or evidence files were changed.

The review covered the Streamlit entry point and pages, database schema/access layer, event models and normalization, all four parsers, correlation engine and correlators, graph builder/analyzer/visualizers, reconstruction and PDF reporting, evaluation and experiment modules, scripts, existing tests, README, and existing research/validation documents. The project inventory contains 55 Python files (including backup copies), six test modules, three existing Markdown documents under `docs/`, a 542,986,240-byte SQLite database, and a large local data tree. The database and data files were inspected only by metadata; their contents were not altered.

## Executive summary

The project has substantial working functionality: separate parsers for Procmon, Sysmon XML, Registry exports, and network evidence; case-scoped SQLite records; timestamp/provenance fields; PID epoch tracking; exact forward/reverse tuple matching; an evidence graph; timeline/narrative/PDF generation; synthetic scenarios; and a Streamlit UI. Existing tests cover many important behaviors, including PID reuse, static Registry snapshots, timestamp uncertainty, graph paths, atomic ingestion, and the timeline source-filter regression.

The main risks are not missing top-level features. They are data lifecycle protections, accidental overwriting of existing evaluation results, inconsistent correlation controls, and gaps between documented research claims and the behavior of the implementation. These should be addressed before using the application for further evidence ingestion or drawing conclusions from ablation results.

## Architecture reviewed

| Area | Main implementation |
|---|---|
| Streamlit navigation and UI | `app/main.py`, `app/pages/`, `app/components/` |
| SQLite schema and data access | `database/db.py`, `database/models.py` |
| Parsing and normalization | `parsers/`, `normalization/normalizer.py` |
| Correlation | `correlation/correlation_engine.py`, `process_correlation.py`, `registry_correlation.py`, `network_correlation.py` |
| Graph and reconstruction | `graph/`, `reconstruction/` |
| Evaluation and experiment data | `evaluation/`, `experiments/`, `scripts/` |
| Tests | `tests/` |
| Research and validation documentation | `README.md`, `docs/`, `reports/`, `output/reports/` |

## Findings

Severity is a project-risk prioritization, not a vulnerability score. Finding IDs are stable references, not severity rankings.

### High priority

#### F-01 — Uploading a same-named artifact overwrites the previously saved raw file

`app/pages/evidence_upload.py:40-45` always writes to `data/raw/<case_id>/<uploaded filename>` using `"wb"`. There is no collision check, immutable naming scheme, or refusal to overwrite. Uploading another file with the same name replaces the prior bytes before the new hash is recorded. This can destroy the original uploaded artifact and break the provenance value of the earlier evidence-file row.

#### F-02 — The controlled generator can replace an active case's normalized data and labels

The lab generator uses fixed artifact filenames beneath `data/test_cases/<case_id>`, writes those files directly, and saves the manifest and ground truth under that same case ID (`experiments/test_scenario_generator.py`). The Evidence Ingestion page passes the currently active case ID to the generator, then invokes `replace_case_ingestion` (`app/pages/evidence_upload.py:338-341`). That database function intentionally replaces the case's prior event, relationship, and evidence-file records (`database/db.py:355-402`). Ground-truth saving also replaces the case's existing ground-truth records and JSON file (`experiments/ground_truth_manager.py:20-74`, `database/db.py:756-762`).

The operation is transactional for the database ingestion itself, but there is no case-type guard or confirmation that the selected case is disposable synthetic data. Using this control on an existing investigation can therefore replace its normalized case contents and ground truth. This does not by itself delete files under `data/raw/`, but it can sever the application's case records from those originals.

#### F-03 — Evaluation runs on page renders and reuses a replacing run ID

`app/pages/evaluation.py:68-134` creates `run_bench_btn` but does not use it to guard the benchmark block. Baseline evaluation and `save_evaluation_run` execute during the page render rather than only after an explicit click. The generated run ID is deterministic for the case, method prefix, and window; `database/db.py:725-734` uses `INSERT OR REPLACE`. Reopening the page or changing an unrelated widget can therefore replace the stored row for that method/window instead of preserving a distinct evaluation run. The ablation and sensitivity tab bodies are also evaluated eagerly by Streamlit.

#### F-04 — Missing or ambiguous network fields can produce invalid five-tuples

`parsers/network_parser.py:103-125` substitutes `"TCP"` when a Protocol column is absent, and also uses `"TCP"` when a row's protocol field is empty. This creates a transport value not present in the evidence. Separately, `Normalizer.normalize_transport_protocol` returns `"OTHER"` for unrecognized values, while `NetworkCorrelator._is_valid_five_tuple` rejects `"UNKNOWN"` but accepts `"OTHER"` (`normalization/normalizer.py:219-244`, `correlation/network_correlation.py:62-68`). Exact equality of two non-transport `"OTHER"` values can therefore satisfy the current protocol component check. The protocol mapping also maps application labels such as DNS to UDP without resolving cases such as DNS over TCP.

`Normalizer.normalize_ip` returns unparseable input as a lowercased string (`normalization/normalizer.py:207-216`), and the five-tuple check only requires truthy address strings. Port values are converted to integers without enforcing the transport-port range. Invalid addresses or ports can therefore remain eligible for matching when the same malformed values occur on both records.

#### F-05 — Correlation feature switches do not isolate the features their labels describe

`use_five_tuple_matching=False` causes the direct Sysmon Event ID 3-to-process attribution loop to skip entirely (`correlation/network_correlation.py:215-219`), even though this relationship is based on ProcessGuid/PID lifetime and is not a wire five-tuple match. Conversely, the Sysmon-to-wire loop does not consult this flag (`network_correlation.py:274-289`); in the ablation it is effectively disabled by separately blanking tuple fields. This makes the option's behavior inconsistent and confounds the five-tuple ablation.

The timestamp ablation is also not a true removal of temporal constraints: the engine substitutes a 100,000-second window for process/network correlation, while Registry correlation still receives `self.temporal_window` (`correlation/correlation_engine.py:48-79`). The ablation label says “unbounded” (`evaluation/ablation.py:68-82`), but 100,000 seconds is finite and Registry temporal matching remains bounded by the original value. Results cannot be interpreted as clean, independent feature ablations.

#### F-06 — A process-create candidate is not checked against the parent's active process epoch

`ProcessCorrelator.correlate_process_tree` accepts a `PROCESS_CREATE` candidate when its `created_pid` matches the child PID and its timestamp is within the configured window (`correlation/process_correlation.py:334-354`). The candidate is not checked to ensure its parent PID belonged to that same process epoch at the create time. It compares absolute time delta, so a create record later than the child-start event can also qualify. A stale or future create record associated with a recycled parent PID can therefore be considered alongside the child start. The separate parent-start evidence path does query the active epoch, but does not validate the direct-create candidate.

#### F-07 — Non-zero ProcessGuid values are not format-validated

`parsers/sysmon_parser.py:123-128` and `event_process_guid` (`correlation/process_correlation.py:16-36`) filter empty and all-zero values but otherwise accept arbitrary strings as ProcessGuid identifiers. Malformed values can consequently enter GUID indexes and be treated as process identity. The parser preserves the raw field, but there is no validity status distinguishing a valid GUID from malformed input.

### Medium priority

#### F-08 — Naive complete timestamps can be interpreted as UTC after timezone resolution fails

The upload UI requests a Procmon timezone, but Registry and network CSV parsing call the timestamp normalizer without one. For a complete timestamp without an offset, `_resolve_timezone` returns `None` for an invalid timezone and `parse_timestamp` then uses `timezone.utc` (`normalization/normalizer.py:26-34, 146-150`). `try_parse_complete_datetime` also assigns UTC to naive values (`normalizer.py:61-69`). This conflicts with the warning that UTC is not applied as a silent fallback and can shift chronology for local-wall-clock data. The original timestamp is retained, but the chosen timezone assumption is not consistently surfaced as uncertainty.

#### F-09 — Graph entity IDs merge distinct process instances and network endpoints

`EvidenceGraphBuilder` keys process entities by normalized name and PID (`graph/graph_builder.py:75-88`), not ProcessGuid or process epoch. Reused PIDs with the same name are consequently merged into one graph node. Network entities are keyed only by destination IP and destination port (`graph_builder.py:123-141`), omitting source endpoint, protocol, and connection identity. These nodes are useful summaries but do not represent unique process instances or sockets.

The proposed evaluation method separately builds an undirected `MultiGraph` and performs a bounded breadth-first expansion (`evaluation/baselines.py:464-505`). It does not use the UI's evidence graph builder or preserve relationship direction during that expansion. This differs from the directed “causal path” description in the UI and research materials.

#### F-10 — Large cases incur avoidable in-memory and pairwise work

`app/pages/evidence_analysis.py:32-39, 148-160` loads every event in the case and constructs Python counts, filtered lists, and display rows in memory. In the network correlator, each Sysmon network event scans the complete wire-packet list (`correlation/network_correlation.py:274-290`), giving pairwise work proportional to Sysmon connection count multiplied by packet count. The timeline page is paginated, but the evidence browser and network correlation are not indexed/batched by tuple and time.

#### F-11 — Dashboard “anomaly” totals are broad heuristics, not anomaly determinations

`database/db.py:796-804` counts all qualifying relationship types with confidence at least 0.85 as anomalies, alongside explanation text matches. Confidence indicates the correlation rule's support, not whether activity is anomalous or malicious. The dashboard labels the value “Flagged Anomalies”; the count should not be read as a supported maliciousness assessment.

#### F-12 — Generated research outputs have duplicate destinations and inconsistent claim strength

The Streamlit research-report page reads from the repository-level `reports/` directory (`app/pages/research_reports.py:21-23, 60-173`), while PDF generation uses `config.settings.REPORTS_DIR` under `output/reports/`. The report-generation scripts write copies into both roots. The current copies of the ten shared report files have matching SHA-256 hashes, but there is no single canonical output path.

In addition, `scripts/generate_research_reports.py:493` makes a broad claim that the graph substantially improves accuracy and suppresses false positives, and line 544 states that held-out cases were never used for tuning. Those are stronger claims than the more qualified treatment in the refreshed summary and report generator. Generated artifacts can therefore depend on which script last ran.

#### F-13 — Database initialization and some data APIs have implicit replacement semantics

Importing `database.db` calls `init_db()` (`database/db.py:827-828`). On a legacy schema, initialization disables foreign keys, copies rows using `INSERT OR IGNORE`, and drops/replaces the original tables (`db.py:23-110`). The migration does not report ignored-row counts. Elsewhere, `insert_events_batch` uses `INSERT OR REPLACE` (`db.py:321-350`), and `clear_events_for_case`, `replace_case_ingestion`, and `save_ground_truth` delete existing rows. These may be intended operations, but imports and API calls are not read-only and replacement behavior needs explicit operator safeguards around forensic data.

### Lower priority / maintainability

#### F-14 — Test execution is not isolated by the repository's default setup

The atomic-ingestion suite redirects its database to a temporary file, but `test_backend.py` and `test_audit.py` use the configured database and generator paths. They create or update cases, synthetic test-case files, ground-truth JSON/database rows, and experiment manifests. `test_audit.py` also writes a temporary corrupt CSV relative to the current directory. A normal test invocation from the project directory can therefore change project-local state. The repository has no `conftest.py`, pytest configuration, or pytest entry in `requirements.txt`; pytest is nevertheless required by two test modules.

#### F-15 — Evaluation assumptions and safeguards need clearer test coverage

The baseline seed heuristic treats every PID whose process name is not in a small exact-name exclusion list as a suspect PID (`evaluation/baselines.py:30-57`). The evaluation then propagates event labels from those seeds. This can make benign user processes part of the predicted incident set. Existing tests cover important individual invariants, but do not cover the page-render overwrite, raw-file collisions, protocol/IP/port validation, feature-switch independence, parent PID reuse and temporal ordering at process creation, ProcessGuid format validation, or the end-to-end report-directory contract.

#### F-16 — Duplicate handling can discard distinct provenance when explicitly called

`Normalizer.deduplicate_events` compares a core event tuple but omits evidence file/reference, ProcessGuid, PPID, protocol, and metadata (`normalization/normalizer.py:312-346`). Distinct source records with matching included fields can be collapsed if this helper is used. No production call site was found; current normal ingestion does not call it. The existing test only checks two records with the same core tuple and does not check preservation of separate provenance.

#### F-17 — Unattributed-packet diagnostics use mutable class-level state

`NetworkCorrelator.last_unattributed_event_ids` is reset and populated as a class attribute (`correlation/network_correlation.py:59, 109, 397-404`). Concurrent correlations in separate Streamlit sessions can overwrite each other's diagnostics. The relationships returned by each call are local, but this shared value can make diagnostics and callers such as the synthetic demo observe another run's packet IDs.

#### F-18 — Supporting-code cleanup and reproducibility are incomplete

`evaluation/sensitivity.py:61` exposes `run_stress_sensitivity` but no call site was found. `ControlledExperimentGenerator.generate_synthetic_incident_dataset` accepts `scenario_name` and `noise_events_count` but ignores them (`experiments/test_scenario_generator.py:477-481`). The tree includes stale report copies in `backup_before_report_fixes/` and a report-generator backup, while the repository has no `pyproject.toml`, pytest configuration, or lint/type-check configuration. `requirements.txt` lists lower bounds but does not declare pytest, and `scikit-learn` appears unused by the Python source.

## Existing positive controls

- Database writes in `replace_case_ingestion` validate inputs and are wrapped in a transaction; its tests verify rollback and preservation of SQLite ground-truth/evaluation rows.
- Sysmon timestamp discrepancy and uncertainty intervals are represented explicitly and have focused regression tests.
- Static `.reg` exports are modeled without fabricated modification timestamps.
- The main network correlation path requires all five tuple fields and includes reverse-direction matching; the corresponding tests pass. The protocol validation issue in F-04 is a gap in what counts as a valid protocol, not a lack of tuple-field checks.
- The timeline source selection has focused AppTest coverage for selection persistence, page navigation, pagination reset, query/export filter consistency, and invalid saved values.
- Existing narrative and PDF content includes objectivity and scope disclaimers.

## Validation performed

The existing pytest suite passed: **56 passed in 4.64 seconds**. It was run with the database, generated evidence, ground truth, manifests, and output directories redirected to a temporary workspace; the temporary workspace was removed after the run. No project SQLite or evidence path was used as a test output target.

This audit did not run ingestion, scenario-generation, report-generation, migration, or database-inspection scripts against the project's existing database or evidence. No performance benchmark or full interactive-browser run was part of Phase 1.

