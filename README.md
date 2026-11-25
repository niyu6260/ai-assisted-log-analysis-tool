# Complete Charger Log Analysis

Local, evidence-based CLI for correlating complete-charger logs. It supports the
current charger platform and keeps unknown evidence visible for manual analysis.

**Pipeline:** discover → parse → normalize → correlate → diagnose → report

## Supported diagnostic layers

- CP / PP physical connection
- PLC / SLAC association
- ISO 15118 / V2G messages
- CCU / VCCU and PCU power control
- OCPP transactions and backend errors
- Link, DNS, TCP, TLS and general network failures

OCPP and VCCU have specialized parsers. Other layers currently use extensible
signature parsers and should be refined with labeled logs from the target platform.

## Quick start

```powershell
cd "C:\AI-assisted log analysis tool"
python -m pip install -e .
python -m charger_log_diag analyze "path\to\YourLog.zip" --out "reports"
```

The previous command remains compatible:

```powershell
python -m ccu_log_diag analyze "path\to\YourLog.zip" --out "reports"
```

An extracted folder can be passed instead of a zip. Add `--keep-work` to retain
the extracted input inside the run folder.

## Outputs

Under `reports/<run_id>/`:

- `timeline.json` – normalized cross-layer events with source locations
- `sessions.json` – correlated charging sessions and layer states
- `findings.json` – rules, known-case matches, evidence and confidence
- `meta.json` – discovered files, unknown logs, domain coverage and stage timings
- `report.md` – human-readable evidence-based diagnosis

An `inconclusive` result is intentional: it lists missing domain logs instead of
inventing a root cause.

## Non-charging incident cases

Network switching, process restart, firmware, payment, meter and other system
incidents must not be analyzed as charging sessions. Define an incident window
and source selection in a case YAML, then run:

```powershell
python -m charger_log_diag analyze-case `
  "cases\solaredge_4g_eth1_manager_conflict\case.yaml"

# Run every case.yaml below cases/ and check expected/forbidden findings
python -m charger_log_diag evaluate-cases "cases"

# Rebuild metrics quickly from each case's latest complete analysis
python -m charger_log_diag evaluate-cases "cases" `
  --reuse-from "reports\incidents"
```

`evaluate-cases` writes both `evaluation.json` and `evaluation.md`. The quality
baseline includes expected-finding recall, forbidden-finding case rate,
selected-file parse success, evidence-producing source coverage, evidence
reference validity, diagnostic-domain coverage, and median/P95 runtime.
Use `--reuse-from` for routine reporting when the underlying completed analyses
are still valid. Re-run only affected cases after parser, detector, source
selection, or input-log changes, then rebuild the cached baseline.

This command is a **routed case regression**: each labeled case names its
registered detector. A 100% result proves that known behavior has not regressed;
it is not evidence of accuracy on unknown incidents. Unknown-log performance
must be measured separately using the withheld-label procedure in
`blind_tests/README.md`.

The case definition records the input archive, exact UTC window, charger serial
number, accepted SN+V module logs, explicitly allowed global logs, expert ground
truth, missing proof, expected findings and forbidden false positives. Output is
written under `reports/incidents/<case_id>/<run_id>/`.

For a new case, copy the existing case YAML as a template and change:

1. `id`, `title`, `input` and `incident` window.
2. `source_selection.modules` and any necessary `include_files` exceptions.
3. The expert assessment and its confidence; use `probable` when evidence is
   causal but does not directly prove the root cause.
4. Expected and forbidden findings.

## Vendor error codes

Keep reusable error-code semantics under `knowledge/error_codes/<vendor>.yaml`.
For example, Sungrow `S3` is defined in `knowledge/error_codes/sungrow.yaml` as
`EV_E_Stop` with origin `vehicle`. Error codes describe observed symptoms or stop
categories; they must not be treated as the underlying root cause without
supporting timeline evidence.

Add future codes in this form:

```yaml
codes:
  S3:
    canonical_event: vehicle_emergency_stop
    meaning: EV_E_Stop
    origin: vehicle
    diagnostic_role: symptom
    confidence: high
```

Case-specific hypotheses and evidence remain in `cases/<case_id>/case.yaml`; do
not put customer-specific conclusions in the shared error-code catalog.

## Diagnostic architecture knowledge

Keep sanitized component responsibilities, communication paths, diagnostic
routing, and evidence boundaries under `knowledge/architecture/`. The initial
TCU/CCU architecture is stored in
`knowledge/architecture/tcu_ccu_diagnostic.yaml`.
It also records size-driven log rotation, asynchronous pipe queues, the
hierarchical state-machine switching sequence, business states, and task
execution boundaries. Rotated `old` and `current` logs must be treated as one
timeline; a rotation boundary is not a reboot or session boundary.

Raw design documents and screenshots marked confidential must remain outside the
repository. The architecture YAML records only diagnostic facts and source
section/page references. A `partial` status means the component topology is
known but message fields, timeouts, retry behavior, fault lifecycle rules, or
model differences still need authoritative sources.

Load and validate this knowledge with:

```python
from pathlib import Path

from ccu_log_diag.architecture_knowledge import load_architecture_knowledge

architecture = load_architecture_knowledge(
    Path("knowledge/architecture/tcu_ccu_diagnostic.yaml")
)
ccu_paths = architecture.paths_for("ccu_charging_controller")
```

Protocol guidance is stored separately under `knowledge/protocols/`.
`iec_61851_cp.yaml` records CP base states and PWM variants, validated
transitions, DIN/ISO message-phase alignment, DC start/stop ordering, and
evidence-safe diagnostic rules. It is marked `partial`: training material is
useful for diagnosis but does not replace licensed normative standards or define
hard timing and voltage-tolerance thresholds.

The complete IDC180 and IDC480 tables are stored under `models` in the same YAML.
Re-import revised Excel workbooks with:

```powershell
python -m pip install -e ".[excel]"
python scripts\import_sungrow_error_codes.py `
  --idc180 "C:\path\IDC180故障总表.xlsx" `
  --idc480 "C:\path\IDC480故障总表.xlsx" `
  --out "knowledge\error_codes\sungrow.yaml"
```

Use `load_error_catalog(path, model="<charger model>")` when looking up a
model-specific internal or OCPP vendor error code. `30E`, `30R-1000`, and
`180E` resolve to the IDC180 table; `480E` and `480EC` resolve to the IDC480
table. The canonical names `IDC180` and `IDC480` are also accepted.

## Layout

```text
charger_log_diag/ public CLI and package
ccu_log_diag/     compatibility package and analysis implementation
rules/            rule metadata and thresholds
knowledge/        confirmed case signatures
cases/            labeled charging and non-charging case definitions
tests/            parser, correlation, detector and pipeline regressions
reports/          analysis outputs
```

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m charger_log_diag evaluate "tests\fixtures\labeled\manifest.yaml"
```

For every confirmed field issue, add a minimized and anonymized fixture plus its
expected root cause before extending a parser or detector. Parsers extract facts;
Python detectors evaluate temporal/cross-layer behavior; YAML stores rule metadata
and tunable thresholds. The evaluation command reports Top-1 accuracy, false-positive
rate, inconclusive rate, parse coverage and runtime. Large-language-model summarization
is deliberately outside the root-cause decision path.
