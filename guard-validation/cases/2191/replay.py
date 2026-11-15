"""Local replay for PairVul 2191 (CVE-2019-19332, do_cpuid_func).

No model/API calls. Compiles the verbatim vulnerable (before.c), patched
(after.c) and derived ineffective (ineffective.c) / equivalent (equivalent.c)
copies with the local portable compiler under ../../tools/tcc, runs the crafted
*nent = 3/4/5 inputs from input.json, and writes evidence.jsonl + report.json
into results/<run_id>/.

Central question recorded here:
  Does do_cpuid_func let __do_cpuid_func write entry[(*nent)++] when
  *nent >= maxnent (first OOB cell = entry[maxnent])?
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # guard-validation
CASE_DIR = ROOT / "cases" / "2191"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"
HARNESS = CASE_DIR / "do_cpuid_func_harness.c"
LOG_DIR = CASE_DIR / "logs"

VARIANTS = [
    ("before", "before.c"),
    ("after", "after.c"),
    ("ineffective-01", "ineffective.c"),
    ("equivalent-01", "equivalent.c"),
]
EXPECTED = {"before": True, "after": False, "ineffective-01": True, "equivalent-01": False}


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
        "ineffective_sha256": digest(CASE_DIR / "ineffective.c"),
        "equivalent_sha256": digest(CASE_DIR / "equivalent.c"),
        "harness_sha256": digest(HARNESS),
    })
    env_hash = digest(out / "environment.json")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    exe = out / "do_cpuid_func_harness.exe"
    command = [str(COMPILER), "-std=c99", str(HARNESS), "-o", str(exe)]
    build = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if build.returncode != 0:
        raise SystemExit("Build failed:\n" + build.stdout + build.stderr)

    evidence = []
    checks = []
    for variant, src in VARIANTS:
        log_parts = ["BUILD\n" + build.stdout + build.stderr]
        observations = []
        triggered = False
        for case in inp["cases"]:
            nent = case["nent"]
            proc = subprocess.run(
                [str(exe), variant, str(nent)],
                capture_output=True, text=True, timeout=5)
            log_parts.append(f"\nEXECUTION nent={nent}\n" + proc.stdout + proc.stderr)
            summary = parse_summary(proc.stdout)
            oob_write = summary.get("OOB_WRITE") == "1"
            triggered = triggered or oob_write
            observations.append({
                "case_id": case["id"],
                "nent": nent,
                "return_value": int(summary.get("RET", "-9999")),
                "inner_called": summary.get("INNER_CALLED") == "1",
                "write_index": int(summary.get("WRITE_INDEX", "-1")),
                "oob_write": oob_write,
                "canary_changed": summary.get("CANARY_CHANGED") == "1",
                "note": case["note"],
            })
        log = LOG_DIR / f"{variant}.log"
        log.write_text("".join(log_parts), encoding="utf-8")

        status = "triggered" if triggered else "not_triggered"
        expected = EXPECTED[variant]
        passed = (status == "triggered") == expected
        checks.append({
            "sample_id": f"{inp['pair_id']}:{variant}",
            "passed": passed,
            "status": status,
            "oob_write_observed": triggered,
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
            "validation_method": "local unit replay of do_cpuid_func (stubbed __do_cpuid_func/__do_cpuid_func_emulated perform the entry[(*nent)++] write; OOB write = index >= maxnent, backed by a canary entry)",
            "command": command,
            "execution_command": [str(exe), variant, "<nent>"],
            "environment_digest": env_hash,
            "source_commit": inp["before_commit"] if variant == "before" else inp["after_commit"],
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": 0,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "notes": "maxnent=4. nent=4: before delegates -> entry[4] OOB write; after/effective reject -E2BIG; ineffective-01 checks *nent>maxnent (misses ==) -> still delegates and writes OOB. ineffective/equivalent are derived from after.c, not upstream commits. The callee write is a stand-in for the real __do_cpuid_func OOB write.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    (out / "evidence.jsonl").write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in evidence), encoding="utf-8")
    save(out / "report.json", {
        "run_id": run_id,
        "pair_id": inp["pair_id"],
        "cve_id": inp["cve_id"],
        "fix_commit_title": inp["fix_commit_title"],
        "before_commit": inp["before_commit"],
        "after_commit": inp["after_commit"],
        "checks": checks,
        "all_passed": all(x["passed"] for x in checks),
        "limitation": "The OOB write itself lives in __do_cpuid_func/__do_cpuid_func_emulated; do_cpuid_func is the missing front gate, and the harness stubs the callees to perform the write. Not a full KVM build, not ASan.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    raise SystemExit(run())
