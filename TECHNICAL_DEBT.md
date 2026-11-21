# U-15 Technical Debt

## Status

This is the Phase 1 backlog derived from `CODEBASE_AUDIT.md`. It records work to be considered in later phases; it is not authorization to modify evidence or the existing database. **No Phase 2–8 implementation is included in this audit.**

Priority meanings:

- **P0 — Data protection:** resolve before further ingestion/generation against existing investigations.
- **P1 — Forensic or research correctness:** resolve before relying on affected correlations or evaluation results.
- **P2 — Reliability and scale:** resolve before increasing case size or broadening operational use.
- **P3 — Maintainability:** improve developer reproducibility and reduce confusion.

## Prioritized backlog

### P0 — Preserve original evidence and existing investigations

#### TD-01: Make raw evidence uploads collision-safe

**Observed:** `save_and_ingest_file` writes directly to a case/name-derived path and truncates an existing same-named artifact.

**Acceptance criteria**

- An existing evidence path is never overwritten by a new upload.
- A duplicate-name upload is rejected or assigned a distinct immutable storage path while retaining the submitted name as metadata.
- Hashes are calculated from the exact stored bytes and linked to the immutable artifact.
- Regression tests prove a collision does not change the original bytes or hash.

#### TD-02: Prevent synthetic generation from replacing a non-synthetic case

**Observed:** the active-case generator writes scenario files, manifests, and ground truth under the selected case ID, then replaces normalized events and evidence-file rows.

**Acceptance criteria**

- Synthetic generation is restricted to a new or explicitly designated synthetic case; an existing real/held-out case cannot be selected accidentally.
- Any intentional replacement is separately confirmed and clearly identifies all affected stores before execution.
- Existing case events, evidence-file records, ground truth, manifests, and evaluation history remain unchanged when generation is cancelled or fails.
- A regression test compares pre/post hashes and database rows for a protected case.

#### TD-03: Make test isolation the default

**Observed:** some tests use the configured database and generator directories. The successful Phase 1 run required temporary runtime path redirection.

**Acceptance criteria**

- `pytest` defaults to a temporary database and temporary generated-data/output directories without relying on a custom external harness.
- Test cleanup runs even on failures and never targets project evidence paths.
- A guard test fails if the test database or generated artifact path resolves inside the project evidence/database directories.
- Document one supported command for the full isolated suite.

### P1 — Correct correlation and evaluation behavior

#### TD-04: Preserve evaluation history and gate execution on explicit action

**Observed:** evaluation calculations run on page render; deterministic IDs plus `INSERT OR REPLACE` overwrite same-method/window rows.

**Acceptance criteria**

- Baselines execute only after an explicit “Run Benchmark Suite” action.
- Each run has a unique, reproducible run record without replacing prior completed runs.
- Navigating to the page, changing a filter, or rerendering does not create or alter evaluation rows.
- A UI/database regression test verifies run counts and existing metrics before and after navigation.

#### TD-05: Validate network transport fields from evidence

**Observed:** CSV parsing fills missing protocol with TCP; unknown protocol `OTHER` can be accepted by five-tuple validation.

**Acceptance criteria**

- Missing transport protocol remains missing/unknown and is never fabricated as TCP.
- A packet is eligible for transport five-tuple matching only when protocol evidence resolves to a supported transport protocol.
- Application protocol names are not treated as transport protocol without supporting fields.
- Malformed IPs, ports outside 0–65535, missing fields, and non-transport labels cannot produce an exact tuple match.
- Tests cover omitted/blank protocol columns and common protocol ambiguity.

#### TD-06: Make correlation feature switches orthogonal

**Observed:** the five-tuple option suppresses unrelated Sysmon-to-process attribution and does not consistently gate the Sysmon-to-wire loop; timestamp ablation retains temporal restrictions.

**Acceptance criteria**

- Disabling five-tuple matching changes only the Sysmon/Wireshark matching path; direct Sysmon process attribution remains unchanged.
- Disabling timestamp constraints removes or explicitly defines temporal gating for every correlator, including process, Registry, and network paths.
- Ablation configurations and labels describe actual implementation behavior.
- Tests compare each feature-on/off pair and prove only the intended relationship class changes.

#### TD-07: Bind process creation evidence to the parent process epoch

**Observed:** a matching `PROCESS_CREATE` record is selected by child PID and absolute time window without verifying the parent's active epoch or that creation precedes the child start. Non-zero ProcessGuid values are also accepted without format validation.

**Acceptance criteria**

- Parent create evidence is accepted only when its PID and valid available ProcessGuid identify the parent epoch active at the create timestamp, and its timestamp is not later than the child start.
- Recycled parent PIDs, conflicting process names/guids, and uncertain timestamps do not create an unsupported `SPAWNED` edge.
- Malformed ProcessGuid values are retained as raw provenance but never used as identity keys.
- Multiple valid parent evidence records remain explainable and preserve their separate provenance.
- Regression fixtures include exit/reuse around a child start and missing parent lifecycle evidence.

#### TD-08: Represent timezone assumptions and timestamp uncertainty explicitly

**Observed:** naive complete values are treated as UTC by normalization and by complete-datetime parsing; invalid timezone names can fall back to UTC.

**Acceptance criteria**

- Local wall-clock timestamps require a valid configured timezone or remain incomplete/uncertain.
- UTC assumptions are explicit in metadata and user-facing warnings.
- Invalid timezone input is reported rather than silently converted.
- Tests cover naive UTC, naive local time, invalid timezone, daylight-saving transitions, and comparison of timestamps from different evidence sources.

#### TD-09: Reconcile evaluation heuristics and published claims

**Observed:** the baseline seed heuristic treats most non-system PIDs as suspect, graph expansion is undirected, and one report script emits claims stronger than the refreshed reports.

**Acceptance criteria**

- Event labels and baseline seeds are defined independently of proposed-method predictions and documented for each dataset type.
- Directional relationship semantics are preserved where causal direction is claimed.
- Synthetic, held-out, and real-world results remain separate and accurately scoped.
- Generated reports derive conclusions from measured outputs and the documented annotation scope; no result is described as false-positive suppression or superiority without supporting metrics.
- Tests use benign user-process examples and a relationship whose direction matters.

### P2 — Improve graph fidelity, scale, and operator feedback

#### TD-10: Use process-instance and connection identities in graph entities

**Observed:** process nodes use `(process_name, PID)`; network nodes use only destination IP/port.

**Acceptance criteria**

- Reused PIDs can produce separate process-instance nodes using ProcessGuid/validated epoch identity where available.
- Missing identity fields do not cause unrelated process instances to be merged.
- Network nodes distinguish protocol and connection/socket identity, or are explicitly documented as destination aggregates.
- Graph exports retain evidence provenance and entity keys are stable across deterministic builds.

#### TD-11: Bound memory and correlation work for large cases

**Observed:** the evidence browser loads all events and the Sysmon-to-wire correlator scans packet lists pairwise.

**Acceptance criteria**

- Browsing uses database-side counts, filtering, and pagination.
- Network matching uses an index keyed by valid tuple/direction and a time-range lookup, without dropping uncertainty-window behavior.
- A benchmark uses synthetic scale fixtures and reports runtime/memory for agreed event counts.
- Empty results, malformed timestamps, and dense tuple collisions remain correct.

#### TD-12: Replace heuristic anomaly totals with neutral, explainable labels

**Observed:** high-confidence relationship counts are presented as anomalies.

**Acceptance criteria**

- The UI labels raw rule matches as relationship/support counts unless an independently defined anomaly rule is applied.
- A confidence score is not presented as a maliciousness or anomaly determination.
- Any anomaly rule includes its supporting evidence, limitations, and tests for benign high-confidence process/network activity.

### P3 — Reproducibility and maintenance

#### TD-13: Establish one canonical report output directory

**Observed:** reports are duplicated between `reports/` and `output/reports/`; the UI and PDF generator use different roots.

**Acceptance criteria**

- One configured report directory is used by generators, UI readers, and PDF output.
- Existing deliverables are migrated only with explicit preservation and verified hashes.
- A smoke test generates a report in a temporary directory and confirms the UI reader resolves the same file.

#### TD-14: Add reproducible developer/test tooling and prune stale copies

**Observed:** pytest is not declared, no project pytest/lint/type-check configuration exists, `scikit-learn` appears unused, a generator method ignores arguments, and backup copies remain in the project tree.

**Acceptance criteria**

- Supported Python/dependency versions and test dependencies are documented and installable.
- Test/lint/type-check commands are automated and run in CI or an equivalent local script.
- Unused dependencies and helpers are confirmed by usage review before removal.
- Backup artifacts are archived or clearly excluded from the runtime source tree without deleting user data.

#### TD-15: Make duplicate handling provenance-aware and correlation diagnostics session-local

**Observed:** the exposed deduplication helper omits source-record identity and several event fields, and unattributed-packet IDs are stored in a mutable class attribute.

**Acceptance criteria**

- Duplicate records are merged only under a documented evidence-identity policy; distinct source references remain traceable.
- Deduplication reports retained/merged provenance rather than dropping it.
- Unattributed-packet diagnostics are returned from an individual correlation run rather than stored in shared mutable class state.
- Tests cover same-content records from separate evidence references and concurrent/independent correlation runs.

## Suggested phase mapping

| Later phase | Relevant debt |
|---|---|
| Phase 2 — Forensic reliability | TD-05, TD-07, TD-08 |
| Phase 3 — Correlation engine | TD-05, TD-06, TD-07 |
| Phase 4 — Evidence graph | TD-10 |
| Phase 5 — Dashboard | TD-01, TD-02, TD-11, TD-12 |
| Phase 6 — PDF reports | TD-09, TD-13 |
| Phase 7 — Quality assurance | TD-03, TD-04, TD-05–TD-11 |
| Phase 8 — Documentation | TD-09, TD-13, TD-14 |

The P0 protections should be addressed before using generation or upload workflows with an existing investigation. No phase beyond the Phase 1 audit is marked complete.

