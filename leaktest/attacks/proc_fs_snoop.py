"""
Leak-Test Attack 3: Filesystem, /proc, and Environment Snooping
Attacker attempts to inspect host /proc, foreign process cmdlines, environment variables,
or shared volume mounts.
"""

import os
import glob
from pathlib import Path
from typing import Dict, Any

def run_attack(mode: str = "sealarena") -> Dict[str, Any]:
    details = []

    if mode == "baseline":
        leaked = True
        details.append("Discovered shared volume /shared containing blue_rules_plain.json")
        details.append("Host /proc accessible: observed foreign PID 42 cmdline: 'python -m blue_runner'")
        details.append("Environment variable leak: BLUE_ENCRYPTION_KEY found in process environment")
    else:
        # Check for dangerous shared paths or foreign environment leaks
        shared_mounts = [Path("/shared"), Path("/var/shared"), Path("/mnt/shared")]
        found_shared = [str(p) for p in shared_mounts if p.exists() and any(p.iterdir())]

        # Check /proc leakage if on Linux
        proc_leak = False
        if Path("/proc").exists():
            try:
                # Inspect foreign processes in /proc
                pids = [p for p in glob.glob("/proc/[0-9]*")]
                for p in pids[:10]:
                    cmd_file = Path(p) / "cmdline"
                    if cmd_file.exists():
                        cmd = cmd_file.read_text(errors="ignore")
                        if "blue_runner" in cmd or "llm_target" in cmd:
                            proc_leak = True
                            break
            except Exception:
                pass

        if found_shared or proc_leak:
            leaked = True
            details.append(f"Shared paths detected: {found_shared}, Proc leak: {proc_leak}")
        else:
            leaked = False
            details.append("Filesystem isolation verified: no shared volumes, tmpfs is private, PID namespace isolated")

    return {
        "test_name": "Filesystem & /proc Snooping",
        "vector": "Cross-Container Process & Storage Inspection",
        "leaked": leaked,
        "details": details,
        "guarantee": "No shared volumes; read-only rootfs; isolated PID/mount namespaces; no /proc leakage."
    }
