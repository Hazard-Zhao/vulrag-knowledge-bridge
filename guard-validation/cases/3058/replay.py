"""Local replay for PairVul 3058 (CVE-2021-37576, kvmppc_rtas_hcall).

No model/API calls. Compiles the verbatim vulnerable (before.c), patched
(after.c) and derived ineffective (ineffective.c) copies with the local
portable compiler under ../../tools/tcc, runs the crafted nargs=15/16/17
inputs from input.json, and writes evidence.jsonl + report.json into
results/<run_id>/.

Central questions recorded here:
  1. With nargs == 16, does the function enter the RTAS handler?
  2. When the handler writes rets[0], does that write land outside args.args[0..15]?

ARRAY_SIZE(args.args) == 16, so `args.rets = &args.args[nargs]` places the
return slot at args[nargs]; nargs == 16 is the first out-of-bounds index.
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # guard-validation
CASE_DIR = ROOT / "cases" / "3058"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"
HARNESS = CASE_DIR / "rtas_hcall.c"
LOG_DIR = CASE_DIR / "logs"

VARIANTS = [("before", "before.c"), ("after", "after.c"), ("ineffective", "ineffective.c")]
EXPECTED = {"before": True, "after": False, "ineffective": True}


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
        "harness_sha256": digest(HARNESS),
    })
    env_hash = digest(out / "environment.json")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    exe = out / "rtas_hcall.exe"
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
            nargs = case["nargs"]
            proc = subprocess.run(
                [str(exe), variant, str(nargs)],
                capture_output=True, text=True, timeout=5)
            log_parts.append(f"\nEXECUTION nargs={nargs}\n" + proc.stdout + proc.stderr)
            summary = parse_summary(proc.stdout)
            handler_entered = summary.get("HANDLER_ENTERED") == "1"
            rets_index = int(summary.get("RETS_INDEX", "-1"))
            oob_write = summary.get("OOB_WRITE") == "1"
            triggered = triggered or oob_write
            observations.append({
                "case_id": case["id"],
                "nargs": nargs,
                "return_value": int(summary.get("RET", "-9999")),
                "handler_entered": handler_entered,
                "rets_index": rets_index,
                "oob_write": oob_write,
                "canary0_before": summary.get("CANARY0_BEFORE"),
                "canary0_after": summary.get("CANARY0_AFTER"),
                "canary1_before": summary.get("CANARY1_BEFORE"),
                "canary1_after": summary.get("CANARY1_AFTER"),
                "args15_after": summary.get("ARGS15_AFTER"),
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
            "validation_method": "local unit replay of kvmppc_rtas_hcall (canary-guarded args.args[16], stubbed kernel helpers); not a real KVM guest, not ASan",
            "command": command,
            "execution_command": [str(exe), variant, "<nargs>"],
            "environment_digest": env_hash,
            "source_commit": inp["before_commit"] if variant == "before" else inp["after_commit"],
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": 0,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "notes": "ARRAY_SIZE(args.args)==16. nargs==16 places rets at args.args[16] (first OOB index). The ineffective variant changes >= to > and misses exactly this equality case.",
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
        "limitation": "Local function-level replay of the nargs upper-bound path; not a full kernel build, not ASan, and not a semantic equivalence proof.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    raise SystemExit(run())
