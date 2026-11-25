from __future__ import annotations

import argparse
import json
from pathlib import Path

from ccu_log_diag.evaluation import evaluate_manifest
from ccu_log_diag.datasets import validate_dataset
from ccu_log_diag.generalization import (
    blind_evaluation_markdown,
    evaluate_frozen_blind_batch,
)
from ccu_log_diag.incident_evaluation import (
    evaluate_incident_cases,
    incident_evaluation_markdown,
)
from ccu_log_diag.incident_pipeline import analyze_incident_case
from ccu_log_diag.pipeline import analyze_logs


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def analyze(
    input_path: Path,
    out_dir: Path,
    rules_path: Path | None = None,
    *,
    keep_work: bool = False,
) -> Path:
    if rules_path is None:
        rules_path = _project_root() / "rules" / "pack_v1.yaml"
    return analyze_logs(
        input_path,
        out_dir,
        rules_path,
        keep_work=keep_work,
    ).run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evidence-based complete charger log analysis")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Analyze a log zip or extracted folder")
    p_an.add_argument("input", type=Path, help="Path to .zip or folder")
    p_an.add_argument("--out", type=Path, default=_project_root() / "reports", help="Output directory")
    p_an.add_argument("--rules", type=Path, default=None, help="Rules YAML path")
    p_an.add_argument("--keep-work", action="store_true", help="Keep extracted input files")
    p_eval = sub.add_parser("evaluate", help="Run labeled-case regression manifest")
    p_eval.add_argument("manifest", type=Path, help="Path to labeled cases YAML")
    p_eval.add_argument("--out", type=Path, default=_project_root() / "reports" / "evaluation")
    p_eval.add_argument("--rules", type=Path, default=_project_root() / "rules" / "pack_v1.yaml")
    p_case = sub.add_parser("analyze-case", help="Analyze a labeled non-charging incident")
    p_case.add_argument("case", type=Path, help="Path to incident case YAML")
    p_case.add_argument("--out", type=Path, default=_project_root() / "reports" / "incidents")
    p_case.add_argument("--keep-work", action="store_true", help="Keep extracted input files")
    p_cases = sub.add_parser("evaluate-cases", help="Run all non-charging incident cases")
    p_cases.add_argument("cases_dir", type=Path, help="Directory containing case.yaml files")
    p_cases.add_argument("--out", type=Path, default=_project_root() / "reports" / "incident-evaluation")
    p_cases.add_argument(
        "--reuse-from",
        type=Path,
        default=None,
        help="Build metrics from each case's latest complete run under this directory",
    )
    p_dataset = sub.add_parser(
        "dataset-validate",
        help="Validate versioned golden cases and split leakage",
    )
    p_dataset.add_argument(
        "dataset_dir",
        type=Path,
        help="Directory containing datasets/cases/<case_id>/case.yaml",
    )
    p_dataset.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional JSON validation report path",
    )
    p_blind = sub.add_parser(
        "evaluate-blind",
        help="Score frozen automatic outputs against revealed blind labels",
    )
    p_blind.add_argument("frozen", type=Path)
    p_blind.add_argument("labels", type=Path)
    p_blind.add_argument(
        "--out",
        type=Path,
        default=_project_root() / "reports" / "blind-evaluation",
    )

    args = parser.parse_args(argv)
    if args.cmd == "analyze":
        if not args.input.exists():
            print(f"Input not found: {args.input}")
            return 1
        run_dir = analyze(args.input, args.out, args.rules, keep_work=args.keep_work)
        print(f"Done. Report: {run_dir / 'report.md'}")
        print(f"Findings: {run_dir / 'findings.json'}")
        return 0
    if args.cmd == "evaluate":
        if not args.manifest.exists():
            print(f"Manifest not found: {args.manifest}")
            return 1
        result = evaluate_manifest(args.manifest, args.rules, args.out)
        args.out.mkdir(parents=True, exist_ok=True)
        output = args.out / "evaluation.json"
        output.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Cases passed: {result.passed}/{result.total}")
        print(f"Top-1 accuracy: {result.top1_accuracy:.1%}")
        print(f"False-positive rate: {result.false_positive_rate:.2f}")
        print(f"Evaluation: {output}")
        return 0 if result.passed == result.total else 1
    if args.cmd == "analyze-case":
        if not args.case.exists():
            print(f"Case file not found: {args.case}")
            return 1
        result = analyze_incident_case(args.case, args.out, keep_work=args.keep_work)
        print(f"Done. Incident report: {result.run_dir / 'report.md'}")
        print(f"Finding: {result.findings[0].rule_id}")
        return 0
    if args.cmd == "evaluate-cases":
        if not args.cases_dir.is_dir():
            print(f"Cases directory not found: {args.cases_dir}")
            return 1
        result = evaluate_incident_cases(
            args.cases_dir,
            args.out,
            reuse_from=args.reuse_from,
        )
        args.out.mkdir(parents=True, exist_ok=True)
        output = args.out / "evaluation.json"
        output.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        report = args.out / "evaluation.md"
        report.write_text(
            incident_evaluation_markdown(result),
            encoding="utf-8",
        )
        print(f"Incident cases passed: {result.passed}/{result.total}")
        print(f"Expected-finding recall: {result.expected_finding_recall:.1%}")
        print(
            "Forbidden-finding case rate: "
            f"{result.false_positive_case_rate:.1%}"
        )
        print(
            "Selected-file parse success: "
            f"{result.average_parse_success_rate:.1%}"
        )
        print(
            "Evidence-reference validity: "
            f"{result.evidence_reference_validity:.1%}"
        )
        print(f"Evaluation: {output}")
        print(f"Baseline report: {report}")
        return 0 if result.total and result.passed == result.total else 1
    if args.cmd == "dataset-validate":
        if not args.dataset_dir.is_dir():
            print(f"Dataset directory not found: {args.dataset_dir}")
            return 1
        result = validate_dataset(args.dataset_dir)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        print(f"Golden cases valid: {result.valid}/{result.files}")
        print(f"Split leakage groups: {len(result.leakage_groups)}")
        for issue in result.issues:
            print(f"{issue.severity}: {issue.path}: {issue.message}")
        return 0 if result.passed and result.files else 1
    if args.cmd == "evaluate-blind":
        if not args.frozen.is_file() or not args.labels.is_file():
            print("Frozen output or label file not found")
            return 1
        result = evaluate_frozen_blind_batch(args.frozen, args.labels)
        args.out.mkdir(parents=True, exist_ok=True)
        json_path = args.out / "evaluation.json"
        report_path = args.out / "evaluation.md"
        json_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        report_path.write_text(
            blind_evaluation_markdown(result),
            encoding="utf-8",
        )
        print(
            f"Blind labels scored: "
            f"{result['revealed_cases']}/{result['total_cases']}"
        )
        print(
            f"Root-cause Top-3 accuracy: "
            f"{result['root_cause_top3_accuracy']:.1%}"
        )
        print(f"Evaluation: {json_path}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
