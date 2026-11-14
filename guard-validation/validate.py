"""Offline local-contract validation for the guard-validation side.

No model/API calls. Compiles each recorded harness with the local portable
compiler under tools/tcc, runs the fixed input grid, and writes evidence.jsonl
plus report.json into an independent results/<run_id>/ directory.

Schema: ../shared/alignment-schema.json. Join keys with the baseline side are
(run, pair_id, sample_id, code_sha256); local-dev evidence leaves run null.
"""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples" / "cpuid"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"

# Variants derived from the upstream after-fix still cite the after revision;
# the original vulnerable version cites the before revision.
BEFORE_VARIANTS = {"original"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def setup():
    """Snapshot is committed with the branch; nothing to fetch from an old copy."""
    if (SAMPLES / "manifest.json").exists():
        print("Snapshot already committed; preserving it.")
        return
    raise SystemExit("Missing samples/cpuid/manifest.json; restore the guard-validation snapshot.")


def run():
    manifest = json.loads((SAMPLES / "manifest.json").read_text(encoding="utf-8"))
    for name, sha in manifest["files"].items():
        if digest(SAMPLES / name) != sha:
            raise RuntimeError(f"Snapshot changed: {name}. Create a new sample version.")
    if not COMPILER.exists():
        raise SystemExit(f"Portable compiler not found: {COMPILER}")

    version = subprocess.run([str(COMPILER), "-v"], capture_output=True, text=True, timeout=10)
    run_id = datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%S%fZ")
    out = ROOT / "results" / run_id
    out.mkdir(parents=True)
    save(out / "environment.json", {
        "python": sys.version,
        "platform": platform.platform(),
        "compiler_version": version.stdout + version.stderr,
        "compiler_sha256": digest(COMPILER),
        "tool_files": {str(p.relative_to(COMPILER.parent)): digest(p)
                       for p in COMPILER.parent.rglob("*") if p.is_file()},
        "manifest_sha256": digest(SAMPLES / "manifest.json"),
    })
    env_hash = digest(out / "environment.json")
    sources = json.loads((SAMPLES / "sources.json").read_text(encoding="utf-8"))
    before_rev = sources[0]["revision"]
    after_rev = sources[1]["revision"]

    evidence, checks = [], []
    top_cve = manifest.get("cve_id")
    top_cwe = manifest.get("cwe")
    for sample in manifest["samples"]:
        variant = sample["variant"]
        harness = SAMPLES / Path(sample["code_path"]).name
        exe = out / (variant + ".exe")
        command = [str(COMPILER), "-std=c99", str(harness), "-o", str(exe)]
        build = subprocess.run(command, capture_output=True, text=True, timeout=30)
        log = out / (variant + ".log")
        observations, status, rc = [], "build_failed", build.returncode
        raw = "BUILD\n" + build.stdout + build.stderr
        if build.returncode == 0:
            try:
                proc = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
                raw += "\nEXECUTION\n" + proc.stdout + proc.stderr
                rc = proc.returncode
                for line in proc.stdout.splitlines():
                    n, func, violation, final_n, ret = map(int, line.split())
                    observations.append({
                        "initial_n": n, "func": func, "write_index": n,
                        "sentinel_changed": bool(violation), "final_n": final_n,
                        "return_value": ret,
                        "path": "target/helper reached" if ret == 0 else "guard rejected",
                    })
                valid_grid = len(observations) == 20 and {
                    (x["initial_n"], x["func"]) for x in observations
                } == {(n, f) for n in range(5) for f in (0, 1, 7, 0x80000000)}
                status = ("triggered" if any(x["sentinel_changed"] for x in observations)
                          else "not_triggered") if rc == 0 and valid_grid else "inconclusive"
            except subprocess.TimeoutExpired:
                status, rc = "timeout", None
                raw += "\nExecution timed out."
        log.write_text(raw, encoding="utf-8")

        expected = sample["expected_violation"]
        passed = status == ("triggered" if expected else "not_triggered")
        checks.append({
            "sample_id": sample["sample_id"], "passed": passed, "status": status,
            "cases": len(observations),
            "changed": sum(x["sentinel_changed"] for x in observations),
        })
        evidence.append({
            "schema_version": 1,
            "run": None,
            "run_id": run_id,
            "pair_id": sample["pair_id"],
            "sample_id": sample["sample_id"],
            "variant": variant,
            "cve_id": sample.get("cve_id", top_cve),
            "cwe": sample.get("cwe", top_cwe),
            "code_sha256": sample["code_sha256"],
            "evidence_id": run_id + ":" + variant,
            "validation_method": "logical-capacity sentinel; not ASan or full kernel execution",
            "command": command,
            "execution_command": [str(exe)],
            "environment_digest": env_hash,
            "source_commit": before_rev if variant in BEFORE_VARIANTS else after_rev,
            "derived_variant": variant,
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": rc,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    (out / "evidence.jsonl").write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in evidence), encoding="utf-8")
    save(out / "report.json", {
        "run_id": run_id, "checks": checks,
        "all_passed": all(x["passed"] for x in checks),
        "total_cases": sum(x["cases"] for x in checks),
        "limitation": "Local fixture checks, not full kernel safety or semantic equivalence proof.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", action="store_true")
    args = parser.parse_args()
    if args.setup:
        setup()
    else:
        raise SystemExit(run())
