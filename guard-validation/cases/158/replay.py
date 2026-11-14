"""Local replay for PrimeVul 158 (CVE-2022-1533, libmobi mobi_decode_infl).

No model/API calls. Compiles the verbatim vulnerable (before.c) and patched
(after.c) copies of mobi_decode_infl with the local portable compiler under
../../tools/tcc, runs the crafted canary-guarded input from input.json, and
writes evidence.jsonl + report.json into results/<run_id>/.

The central question recorded here: in the delete branch (`dir == '<'`),
after `pos--`, does `pos` become negative, and does the code intercept early
or keep reading `decoded[pos]`? The upstream debug_print messages in the log
show `pos: -1` for both versions; the vulnerable version then reads
`decoded[-1]` while the patched version returns MOBI_DATA_CORRUPT first.
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # guard-validation
CASE_DIR = ROOT / "cases" / "158"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"
HARNESS = CASE_DIR / "mobi_decode_infl.c"
LOG_DIR = CASE_DIR / "logs"                        # committed execution logs


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_summary(line):
    items = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            items[k] = v
    return items


def run():
    if not COMPILER.exists():
        raise SystemExit(f"Portable compiler not found: {COMPILER}")
    inp = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    version = subprocess.run([str(COMPILER), "-v"], capture_output=True, text=True, timeout=10)

    run_id = datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%S%fZ")
    out = ROOT / "results" / run_id
    out.mkdir(parents=True)

    save(out / "environment.json", {
        "python": sys.version,
        "platform": platform.platform(),
        "compiler_version": version.stdout + version.stderr,
        "compiler_sha256": digest(COMPILER),
        "input_sha256": digest(CASE_DIR / "input.json"),
        "before_sha256": digest(CASE_DIR / "before.c"),
        "after_sha256": digest(CASE_DIR / "after.c"),
        "harness_sha256": digest(HARNESS),
    })
    env_hash = digest(out / "environment.json")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    exe = out / "mobi_decode_infl.exe"
    command = [str(COMPILER), "-std=c99", str(HARNESS), "-o", str(exe)]
    build = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if build.returncode != 0:
        raise SystemExit("Build failed:\n" + build.stdout + build.stderr)

    evidence = []
    checks = []
    for variant, src in (("before", "before.c"), ("after", "after.c")):
        log_parts = ["BUILD\n" + build.stdout + build.stderr]
        observations = []
        oob_read = oob_write = False
        for case in inp["cases"]:
            case_id = case["id"]
            proc = subprocess.run(
                [str(exe), case_id, variant, case["decoded_ascii"],
                 str(case["canary_dec"]), case["rule_hex"]],
                capture_output=True, text=True, timeout=5)
            log_parts.append(f"\nEXECUTION {case_id}\n" + proc.stdout + proc.stderr)
            summary = parse_summary(proc.stdout)
            canary_changed = summary.get("CANARY_BEFORE") != summary.get("CANARY_AFTER")
            read_here = "Character mismatch" in proc.stderr
            oob_read = oob_read or read_here
            oob_write = oob_write or canary_changed
            observations.append({
                "case_id": case_id,
                "decoded_ascii": case["decoded_ascii"],
                "canary_dec": case["canary_dec"],
                "rule_hex": case["rule_hex"],
                "return_value": int(summary.get("RET", "-1")),
                "decoded_size_after": int(summary.get("DECODED_SIZE", "-1")),
                "canary_before": int(summary.get("CANARY_BEFORE", "-1")),
                "canary_after": int(summary.get("CANARY_AFTER", "-1")),
                "canary_changed": canary_changed,
                "decoded0_after": int(summary.get("DECODED0", "-1")),
                "oob_read_observed": read_here,
                "intercepted_at_neg_pos": "Out of buffer" in proc.stderr and "pos: -1" in proc.stderr,
                "note": case["note"],
            })
        log = LOG_DIR / f"{variant}.log"
        log.write_text("".join(log_parts), encoding="utf-8")

        status = "triggered" if (oob_read or oob_write) else "not_triggered"
        expected = variant == "before"
        passed = (status == "triggered") == expected
        checks.append({
            "sample_id": f"{inp['pair_id']}:{variant}",
            "passed": passed,
            "status": status,
            "oob_read_observed": oob_read,
            "oob_write_observed": oob_write,
        })
        evidence.append({
            "schema_version": 1,
            "run": None,
            "run_id": run_id,
            "pair_id": inp["pair_id"],
            "sample_id": f"{inp['pair_id']}:{variant}",
            "variant": variant,
            "cve_id": inp["cve_id"],
            "cwe": inp["cwe"],
            "code_sha256": digest(CASE_DIR / src),
            "evidence_id": f"{run_id}:{variant}",
            "validation_method": "local unit replay of mobi_decode_infl (canary-guarded buffer, crafted rule); not a full .mobi parse, not ASan",
            "command": command,
            "execution_command": [str(exe), "<case_id>", variant, "<decoded_ascii>", "<canary_dec>", "<rule_hex>"],
            "environment_digest": env_hash,
            "source_commit": inp["before_commit"] if variant == "before" else inp["after_commit"],
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": 0,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "notes": "code_sha256 hashes the extracted verbatim function file (before.c/after.c); reconcile with the baseline testset snippet hash before joining predictions and evidence.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    (out / "evidence.jsonl").write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in evidence), encoding="utf-8")
    save(out / "report.json", {
        "run_id": run_id,
        "pair_id": inp["pair_id"],
        "cve_id": inp["cve_id"],
        "before_commit": inp["before_commit"],
        "after_commit": inp["after_commit"],
        "checks": checks,
        "all_passed": all(x["passed"] for x in checks),
        "limitation": "Local function-level replay of the delete-branch pos-- path; not a full libmobi build, not ASan, and not a semantic equivalence proof.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    raise SystemExit(run())
