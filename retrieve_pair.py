"""Compare two versions with a local Vul-RAG knowledge JSON."""

import argparse
import hashlib
import json
from pathlib import Path

import spacy
from rank_bm25 import BM25Okapi


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compact(code):
    return "".join(code.split())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb", type=Path, required=True)
    parser.add_argument("--source", required=True, help="Knowledge repository and revision")
    parser.add_argument("--vulnerable", type=Path, required=True)
    parser.add_argument("--patched", type=Path, required=True)
    parser.add_argument("--exclude-cve", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    paths = {"vulnerable": args.vulnerable, "patched": args.patched}
    inputs = {key: path.read_bytes() for key, path in paths.items()}
    queries = {key: data.decode("utf-8-sig") for key, data in inputs.items()}
    excluded_code = {compact(code) for code in queries.values()}
    excluded_cves = {cve.upper() for cve in args.exclude_cve}
    kb_data = args.kb.read_bytes()
    rows = json.loads(kb_data.decode("utf-8-sig"))
    if not isinstance(rows, list) or not rows:
        parser.error("Expected a nonempty Vul-RAG knowledge JSON array")

    corpus = [
        row for row in rows
        if row["CVE_id"].upper() not in excluded_cves
        and compact(row["code_before_change"]) not in excluded_code
        and compact(row["code_after_change"]) not in excluded_code
    ]
    if not corpus:
        parser.error("No candidates remain after overlap filtering")

    nlp = spacy.load("en_core_web_sm")

    def tokens(doc):
        return [token.text.lower() for token in doc if not token.is_punct]

    index = BM25Okapi([
        tokens(doc)
        for doc in nlp.tokenizer.pipe(row["code_before_change"] for row in corpus)
    ])

    def retrieve(code):
        scores = index.get_scores(tokens(nlp.make_doc(code)))
        ranked = sorted(range(len(corpus)), key=lambda i: (-scores[i], i))
        hits = []
        seen = set()
        for i in ranked:
            row = corpus[i]
            cve = row["CVE_id"].upper()
            if cve in seen or scores[i] <= 0:
                continue
            seen.add(cve)
            behavior = row.get("vulnerability_behavior") or row
            hits.append({
                "id": row.get("id"),
                "score": float(scores[i]),
                "knowledge": {
                    "cve_id": cve,
                    "vulnerability_behavior": {
                        "vulnerability_cause_description": (
                            behavior.get("vulnerability_cause_description")
                            or behavior.get("preconditions_for_vulnerability")
                        ),
                        "trigger_condition": behavior.get("trigger_condition"),
                        "specific_code_behavior_causing_vulnerability": behavior.get(
                            "specific_code_behavior_causing_vulnerability"
                        ),
                    },
                    "solution_behavior": row["solution"],
                },
            })
            if len(hits) == 3:
                break
        return hits

    hits = {key: retrieve(code) for key, code in queries.items()}
    if any(len(items) < 3 for items in hits.values()):
        parser.error("Fewer than three positive-scoring CVEs for at least one version")
    report = {
        "source": args.source,
        "knowledge_file": args.kb.name,
        "knowledge_sha256": digest(kb_data),
        "entries_before": len(rows),
        "entries_after": len(corpus),
        "excluded_cves": sorted(excluded_cves),
        "retrieval": "code-only BM25Okapi, one hit per CVE",
        "input_sha256": {key: digest(data) for key, data in inputs.items()},
        "hits": hits,
    }
    args.out.mkdir(parents=True)
    outputs = {
        "retrieval.json": report,
        # Freeze one set per pair so B/C/D do not vary knowledge with the patch.
        "fixed_knowledge.json": [hit["knowledge"] for hit in hits["vulnerable"]],
    }
    for name, data in outputs.items():
        path = args.out / name
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
