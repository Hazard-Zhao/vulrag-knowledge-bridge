"""Local replay for PairVul 1349 (CVE-2017-16912, get_pipe).

No model/API calls. Compiles the verbatim vulnerable (before.c), patched
(after.c) and derived ineffective (ineffective.c) / equivalent (equivalent.c)
copies with the local portable compiler under ../../tools/tcc, runs the crafted
epnum=15/16/17 inputs from input.json, and writes evidence.jsonl + report.json
into results/<run_id>/.

Central questions recorded here:
  1. With epnum == 16, does get_pipe() read past ep_in[0..15]?
  2. Which variants reject before the read, and which proceed into the OOB read?

ep_in has 16 elements, indexed by `epnum & 0x7f`; epnum == 16 masks to index 16,
the first out-of-bounds slot. The harness places a canary endpoint marker (0xB2)
immediately after ep_in[15] so the read target is observable.
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # guard-validation
CASE_DIR = ROOT / "cases" / "1349"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"
HARNESS = CASE_DIR / "get_pipe_harness.c"
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

    exe = out / "get_pipe_harness.exe"
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
            epnum = case["epnum"]
            proc = subprocess.run(
                [str(exe), variant, str(epnum)],
                capture_output=True, text=True, timeout=5)
            log_parts.append(f"\nEXECUTION epnum={epnum}\n" + proc.stdout + proc.stderr)
            summary = parse_summary(proc.stdout)
            read_oob = summary.get("READ_OOB") == "1"
            read_valid = summary.get("READ_VALID") == "1"
            triggered = triggered or read_oob
            observations.append({
                "case_id": case["id"],
                "epnum": epnum,
                "return_value": int(summary.get("RET", "-9999")),
                "obs_type": summary.get("OBS_TYPE"),
                "read_oob": read_oob,
                "read_valid": read_valid,
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
            "oob_read_observed": triggered,
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
            "validation_method": "local unit replay of get_pipe (canary endpoint marker 0xB2 after ep_in[15], stubbed usb helpers); not a full kernel build, not ASan",
            "command": command,
            "execution_command": [str(exe), variant, "<epnum>"],
            "environment_digest": env_hash,
            "source_commit": inp["before_commit"] if variant == "before" else inp["after_commit"],
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": 0,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "notes": "ep_in has 16 elements indexed by epnum & 0x7f; epnum==16 masks to index 16 (first OOB). ineffective-01 weakens epnum>15 to epnum>16 and misses exactly epnum==16; equivalent-01 rewrites epnum>15 as epnum>=16 and still rejects 16.",
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
        "limitation": "Local function-level replay of the epnum upper-bound OOB-read path; not a full kernel build, not ASan, and not a semantic equivalence proof.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    raise SystemExit(run())
