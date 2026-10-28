#!/usr/bin/env python3
"""
SealArena Leak-Test Orchestration Harness
Executes all 9 automated attack vectors against (A) Naive Baseline and (B) SealArena,
quantifies timing side-channels, and outputs the comparative scoreboard.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from leaktest.attacks import (
    net_scan,
    dns_snoop,
    proc_fs_snoop,
    docker_escape,
    timing_probe,
    cache_probe,
    canary_exfil,
    log_tamper,
    resource_exhaust
)
from leaktest.scoreboard import format_terminal_scoreboard

ATTACK_MODULES = [
    net_scan,
    dns_snoop,
    proc_fs_snoop,
    docker_escape,
    timing_probe,
    cache_probe,
    canary_exfil,
    log_tamper,
    resource_exhaust
]

RESULTS_JSON_PATH = PROJECT_ROOT / "data" / "leaktest_results.json"

def run_suite() -> Dict[str, Any]:
    print("[*] Launching SealArena Automated Leak-Test Suite against both environments...\n")

    baseline_results: List[Dict[str, Any]] = []
    sealarena_results: List[Dict[str, Any]] = []

    for mod in ATTACK_MODULES:
        b_res = mod.run_attack("baseline")
        s_res = mod.run_attack("sealarena")
        baseline_results.append(b_res)
        sealarena_results.append(s_res)

    # Format Scoreboard
    scoreboard_text = format_terminal_scoreboard(baseline_results, sealarena_results)
    print(scoreboard_text)

    # Calculate summary metrics
    b_leaks = sum(1 for r in baseline_results if r["leaked"])
    s_leaks = sum(1 for r in sealarena_results if r["leaked"])
    total = len(ATTACK_MODULES)

    summary_data = {
        "timestamp": time.time(),
        "total_tests": total,
        "baseline_leaks": b_leaks,
        "sealarena_leaks": s_leaks,
        "baseline_results": baseline_results,
        "sealarena_results": sealarena_results,
        "scoreboard_text": scoreboard_text
    }

    try:
        RESULTS_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)
    except OSError:
        tmp_path = Path("/tmp/leaktest_results.json")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=2)
        except Exception:
            pass

    return summary_data

if __name__ == "__main__":
    run_suite()
