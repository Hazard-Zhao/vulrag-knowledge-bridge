"""Offline alignment checker for baseline predictions and guard evidence.

Stdlib only. Joins predictions.jsonl and evidence.jsonl on
(run, pair_id, sample_id, code_sha256) and reports every mismatch explicitly;
it never drops or overwrites rows.

Usage:
    python -X utf8 shared/validate_alignment.py \
        --predictions results/<run>/predictions.jsonl \
        --evidence results/<run>/evidence.jsonl

Exit code 0 = no hard errors; 1 = missing required fields, bad enums,
duplicate keys, or unmatched join rows. Warnings (e.g. evidence without a
prediction in a standalone local-dev batch) are listed separately.
"""

import argparse
import json
import re
import sys
from pathlib import Path

PAIR_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

PRED_REQUIRED = [
    "run", "pair_id", "sample_id", "variant", "cve_id", "cwe",
    "label", "prediction", "evaluated_knowledge_cves",
]
EVID_REQUIRED = [
    "schema_version", "run", "run_id", "pair_id", "sample_id", "variant",
    "cve_id", "cwe", "code_sha256", "evidence_id", "validation_method",
    "command", "environment_digest", "source_commit", "tool_versions",
    "status", "exit_code", "log_path", "log_sha256", "created_at",
]
VARIANTS = {
    "before", "after", "ineffective-01", "equivalent-01", "caller-01",
    "developer_fix", "original",
}
PREDICTION_VALUES = {1, 0, -1}
LABEL_VALUES = {1, 0}
EVID_STATUS = {
    "triggered", "not_triggered", "inconclusive", "build_failed", "timeout",
}
JOIN_KEYS = ["run", "pair_id", "sample_id", "code_sha256"]


def read_jsonl(path):
    rows = []
    if not path.exists():
        return rows, [f"file not found: {path}"]
    errors = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{lineno} invalid JSON: {exc}")
    return rows, errors


def check_row(row, required, kind, errors, warnings):
    prefix = f"{kind} sample_id={row.get('sample_id', '?')}"
    for field in required:
        if field not in row or row[field] is None:
            errors.append(f"{prefix}: missing required field '{field}'")
    pair_id = row.get("pair_id")
    if pair_id and not PAIR_RE.match(str(pair_id)):
        errors.append(f"{prefix}: pair_id format invalid: {pair_id}")
    sample_id = row.get("sample_id")
    if pair_id and sample_id and not str(sample_id).startswith(str(pair_id) + ":"):
        errors.append(f"{prefix}: sample_id does not derive from pair_id")
    variant = row.get("variant")
    if variant and variant not in VARIANTS:
        warnings.append(f"{prefix}: variant '{variant}' outside the registered set")
    for hash_field in ("code_sha256", "log_sha256"):
        value = row.get(hash_field)
        if value is not None and not SHA_RE.match(str(value)):
            errors.append(f"{prefix}: {hash_field} is not a 64-char sha256")


def index(rows):
    out = {}
    duplicates = []
    for row in rows:
        key = tuple(row.get(k) for k in JOIN_KEYS)
        if key in out:
            duplicates.append(key)
        out.setdefault(key, []).append(row)
    return out, duplicates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()

    errors, warnings = [], []
    preds, e1 = read_jsonl(args.predictions)
    evids, e2 = read_jsonl(args.evidence)
    errors += e1 + e2

    for row in preds:
        check_row(row, PRED_REQUIRED, "prediction", errors, warnings)
        if row.get("label") not in LABEL_VALUES:
            errors.append(f"prediction {row.get('sample_id')}: label must be 0/1")
        if row.get("prediction") not in PREDICTION_VALUES:
            errors.append(f"prediction {row.get('sample_id')}: prediction must be 1/0/-1")
        if not isinstance(row.get("evaluated_knowledge_cves", []), list):
            errors.append(f"prediction {row.get('sample_id')}: evaluated_knowledge_cves must be a list")

    for row in evids:
        check_row(row, EVID_REQUIRED, "evidence", errors, warnings)
        if row.get("status") not in EVID_STATUS:
            errors.append(f"evidence {row.get('sample_id')}: status '{row.get('status')}' invalid")

    pred_idx, pred_dups = index(preds)
    evid_idx, evid_dups = index(evids)
    for key in pred_dups:
        errors.append(f"duplicate prediction join key: {key}")
    for key in evid_dups:
        errors.append(f"duplicate evidence join key: {key}")

    pred_keys, evid_keys = set(pred_idx), set(evid_idx)
    for key in sorted(evid_keys - pred_keys, key=str):
        warnings.append(f"evidence without matching prediction (local-dev batch?): {key}")
    for key in sorted(pred_keys - evid_keys, key=str):
        errors.append(f"prediction without matching evidence: {key}")
    for key in sorted(pred_keys & evid_keys, key=str):
        if len(evid_idx[key]) > 1:
            warnings.append(f"multiple evidence rows for {key}: {len(evid_idx[key])}")

    report = {
        "predictions": len(preds),
        "evidence": len(evids),
        "errors": errors,
        "warnings": warnings,
        "status": "pass" if not errors else "fail",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
