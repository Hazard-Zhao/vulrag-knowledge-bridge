"""Local replay for PairVul 332 (CVE-2013-4587, kvm_vm_ioctl_create_vcpu).

No model/API calls. Compiles the verbatim vulnerable (before.c), patched
(after.c) and derived ineffective (ineffective.c) / equivalent (equivalent.c)
copies with the local portable compiler under ../../tools/tcc, runs the crafted
vcpu_id = 3/4/5 inputs from input.json, and writes evidence.jsonl + report.json
into results/<run_id>/.

Central question recorded here:
  Does kvm_vm_ioctl_create_vcpu proceed to kvm_arch_vcpu_create with an
  out-of-range id (id >= KVM_MAX_VCPUS), the condition the fix's guard blocks?

The downstream OOB (vcpu_id later indexed elsewhere) is not replayed here;
the guard is the unit under test.
"""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # guard-validation
CASE_DIR = ROOT / "cases" / "332"
COMPILER = ROOT / "tools" / "tcc" / "tcc.exe"
HARNESS = CASE_DIR / "kvm_vm_ioctl_create_vcpu_harness.c"
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

    exe = out / "kvm_vm_ioctl_create_vcpu_harness.exe"
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
            vcpu_id = case["vcpu_id"]
            proc = subprocess.run(
                [str(exe), variant, str(vcpu_id)],
                capture_output=True, text=True, timeout=5)
            log_parts.append(f"\nEXECUTION id={vcpu_id}\n" + proc.stdout + proc.stderr)
            summary = parse_summary(proc.stdout)
            guard_bypassed = summary.get("GUARD_BYPASSED") == "1"
            triggered = triggered or guard_bypassed
            observations.append({
                "case_id": case["id"],
                "vcpu_id": vcpu_id,
                "return_value": int(summary.get("RET", "-9999")),
                "arch_create_called": summary.get("ARCH_CREATE_CALLED") == "1",
                "arch_create_id": int(summary.get("ARCH_CREATE_ID", "-1")),
                "guard_bypassed": guard_bypassed,
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
            "guard_bypass_observed": triggered,
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
            "validation_method": "local unit replay of kvm_vm_ioctl_create_vcpu (stubbed kvm_arch_vcpu_create records whether creation proceeded with an out-of-range id; downstream OOB not replayed)",
            "command": command,
            "execution_command": [str(exe), variant, "<id>"],
            "environment_digest": env_hash,
            "source_commit": inp["before_commit"] if variant == "before" else inp["after_commit"],
            "tool_versions": version.stdout + version.stderr,
            "status": status,
            "exit_code": 0,
            "log_path": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
            "observations": observations,
            "notes": "KVM_MAX_VCPUS=4 (stub; upstream 1024). id=4: before/ineffective proceed to kvm_arch_vcpu_create (guard bypassed); after/equivalent return -EINVAL. ineffective-01 checks id>KVM_MAX_VCPUS (misses ==). This is a guard-only replay: the downstream vcpu_id-indexed OOB is out of scope for this unit.",
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
        "limitation": "Guard-only replay: observes whether the id>=KVM_MAX_VCPUS guard is bypassed; the actual vcpu_id-indexed OOB happens in other KVM code and is not reproduced. KVM_MAX_VCPUS stubbed to 4.",
    })
    save(ROOT / "latest.json", {"run_id": run_id, "report": str(out / "report.json")})
    print(json.dumps(checks, indent=2))
    print("Evidence:", out / "evidence.jsonl")
    return 0 if all(x["passed"] for x in checks) else 1


if __name__ == "__main__":
    raise SystemExit(run())
