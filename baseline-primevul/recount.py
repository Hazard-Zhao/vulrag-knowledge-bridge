"""Recompute Vul-RAG RQ2 metrics from the released predictions."""

import argparse
import json
from pathlib import Path
from statistics import mean, stdev


MODEL = "qwen2.5-coder-14b-instruct"
CONFIG = f"{MODEL}__sum-{MODEL}"


def read(path):
    return json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path, help="RAG4SVD checkout root")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.upstream / "systems/vul-rag"
    runs = []
    predictions = []
    expected_ids = None
    for run, suffix in enumerate(("", "_r2", "_r3"), 1):
        folder = root / "benchmark_results_vulrag" / (CONFIG + suffix)
        files = sorted(folder.glob("primevul_CWE-*_result_*.json"))
        if not files:
            raise ValueError(f"No prediction files in {folder}")
        seen = set()
        tp = fp = correct = parsed = 0
        for path in files:
            bucket = path.name.split("_result_")[0]
            test = {r["id"]: r for r in read(root / "data/test" / f"{bucket}_testset.json")}
            for pair in read(path):
                row = test[pair["id"]]
                pair_id = f"rag4svd-rq2:{bucket}:{row['id']}"
                if pair_id in seen:
                    raise ValueError(f"Repeated pair: {pair_id}")
                seen.add(pair_id)
                before, after = (pair[f"detect_result_{side}"] for side in ("before", "after"))
                for side, record in (("before", before), ("after", after)):
                    if record["code_snippet"].strip() != row[f"code_{side}_change"].strip():
                        raise ValueError(f"Input mismatch: {pair_id}/{side}")
                    predictions.append({
                        "run": run, "pair_id": pair_id,
                        "sample_id": f"{pair_id}:{side}", "variant": side,
                        "cve_id": row["cve_id"], "cwe": row["cwe"],
                        "label": int(side == "before"),
                        "prediction": record["final_result"],
                        "evaluated_knowledge_cves": [
                            item["vul_knowledge"]["cve_id"]
                            for item in record["detect_result"]
                        ],
                    })
                v, p = before["final_result"], after["final_result"]
                tp += v == 1
                fp += p == 1
                correct += v == 1 and p != 1
                parsed += v in (0, 1) and p in (0, 1)
        n = len(seen)
        if expected_ids is not None and seen != expected_ids:
            raise ValueError("Pair coverage differs across repetitions")
        expected_ids = seen
        tn, fn = n - fp, n - tp
        precision = ((tp / (tp + fp) if tp + fp else 0)
                     + (tn / (tn + fn) if tn + fn else 0)) / 2
        recall = (tp + tn) / (2 * n)
        metrics = {
            "run": run, "pairs": n, "correct_pairs": correct,
            "pair_accuracy": correct / n,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0,
            "positive_class_f1": 2 * tp / (tp + fp + n),
            "binary_final_result_pair_rate": parsed / n,
            "tp": tp, "fp": fp, "fn": n - tp, "tn": n - fp,
        }
        reference = read(folder / "metrics/total_metrics.json")
        for key in ("pair_accuracy", "f1"):
            if round(metrics[key], 4) != reference[key]:
                raise ValueError(f"Metric mismatch in run {run}: {key}")
        runs.append(metrics)
    values = [r["pair_accuracy"] for r in runs]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "predictions.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in predictions), encoding="utf-8"
    )
    summary = {"runs": runs, "mean_pair_accuracy": mean(values), "sample_std": stdev(values)}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
