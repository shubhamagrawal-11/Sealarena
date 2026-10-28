#!/usr/bin/env python3
"""
SealArena Universal Demo Orchestrator
Starts the complete SealArena multi-tenant secure evaluation sandbox with a single command.
Supports Docker Compose deployment and native zero-dependency subprocess execution.
"""

import os
import sys
import time
import subprocess
import argparse
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def check_docker_available() -> bool:
    """Checks if Docker and Docker Compose are installed and running."""
    try:
        res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def ensure_prerequisites():
    """Ensures mTLS certs and encrypted rules exist."""
    certs_dir = PROJECT_ROOT / "certs"
    if not (certs_dir / "ca.crt").exists():
        print("[*] Generating mTLS PKI certificates...")
        subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "gen_certs.py")], check=True)

    rules_bin = PROJECT_ROOT / "configs" / "encrypted_blue_rules.bin"
    if not rules_bin.exists():
        print("[*] Encrypting Blue defense rules...")
        subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "encrypt_rules.py")], check=True)

def run_native_demo():
    """Runs all microservices natively in coordinated background processes."""
    print("\n" + "=" * 70)
    print("           STARTING SEALARENA IN SECURE NATIVE RUNTIME")
    print("=" * 70)

    processes = []
    try:
        # 1. Start LLM Target (Port 8001)
        print("[1/5] Launching LLM Target (model-net isolation)...")
        p_model = subprocess.Popen([sys.executable, "-m", "src.llm_target.main"], cwd=str(PROJECT_ROOT))
        processes.append(p_model)
        time.sleep(1.0)

        # 2. Start Audit Ledger (Port 8003)
        print("[2/5] Launching Audit Ledger (Ed25519 hash chain)...")
        p_ledger = subprocess.Popen([sys.executable, "-m", "src.audit_ledger.main"], cwd=str(PROJECT_ROOT))
        processes.append(p_ledger)
        time.sleep(1.0)

        # 3. Start Monitor (Port 8004)
        print("[3/5] Launching Observability Monitor (zero-leakage telemetry)...")
        p_monitor = subprocess.Popen([sys.executable, "-m", "src.monitor.main"], cwd=str(PROJECT_ROOT))
        processes.append(p_monitor)
        time.sleep(1.0)

        # 4. Start Arbiter Broker (Port 8000)
        print("[4/5] Launching Arbiter Broker (mTLS gatekeeper, guard & timing defense)...")
        p_arbiter = subprocess.Popen([sys.executable, "-m", "src.arbiter.main"], cwd=str(PROJECT_ROOT))
        processes.append(p_arbiter)
        time.sleep(1.5)

        # 5. Start Dashboard (Port 8080)
        print("[5/5] Launching SOC Operations Dashboard (Port 8080)...")
        p_dash = subprocess.Popen([sys.executable, "-m", "src.dashboard.main"], cwd=str(PROJECT_ROOT))
        processes.append(p_dash)
        time.sleep(1.5)

        # Deploy Blue rules & execute initial Red round
        print("\n[*] Initializing Blue Team encrypted defense rules...")
        subprocess.run([sys.executable, "-m", "src.blue_runner.main"], cwd=str(PROJECT_ROOT), timeout=5)

        print("[*] Executing initial Red Team Commit-Reveal benchmark evaluation...")
        subprocess.run([sys.executable, "-m", "src.red_runner.main"], cwd=str(PROJECT_ROOT))

        print("[*] Running automated Leak-Test Suite to populate scoreboard...")
        subprocess.run([sys.executable, "-m", "leaktest.harness"], cwd=str(PROJECT_ROOT))

        print("\n" + "=" * 70)
        print("          SEALARENA IS FULLY OPERATIONAL AND READY!")
        print("=" * 70)
        print("  >> Web Dashboard:      http://localhost:8080")
        print("  >> Arbiter Broker API: http://localhost:8000")
        print("  >> Audit Ledger API:   http://localhost:8003")
        print("  >> Zero-Leak Monitor:  http://localhost:8004")
        print("=" * 70)
        print("Press Ctrl+C to stop all services.\n")

        try:
            webbrowser.open("http://localhost:8080")
        except Exception:
            pass

        # Keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping all SealArena microservices...")
    finally:
        for p in processes:
            p.terminate()
            p.wait()
        print("[+] All services stopped cleanly.")

def run_docker_demo():
    """Runs all microservices via Docker Compose."""
    print("\n" + "=" * 70)
    print("           STARTING SEALARENA VIA DOCKER COMPOSE")
    print("=" * 70)

    cmd = ["docker", "compose", "up", "--build", "-d"]
    print(f"[*] Executing: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)

    print("\n[*] Waiting for microservices to initialize...")
    time.sleep(5)

    print("[*] Running automated Leak-Test Suite...")
    subprocess.run([sys.executable, "-m", "leaktest.harness"], cwd=str(PROJECT_ROOT))

    print("\n" + "=" * 70)
    print("          SEALARENA IS FULLY OPERATIONAL AND READY!")
    print("=" * 70)
    print("  >> Web Dashboard:      http://localhost:8080")
    print("  >> Arbiter Broker:     https://localhost:8000")
    print("=" * 70)
    print("Run 'docker compose logs -f' to view logs.")
    print("Run 'docker compose down' to stop.\n")

    try:
        webbrowser.open("http://localhost:8080")
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="SealArena Universal Demo Runner")
    parser.add_argument("--native", action="store_true", help="Force native subprocess execution without Docker")
    parser.add_argument("--docker", action="store_true", help="Force Docker Compose execution")
    parser.add_argument("--leaktest", action="store_true", help="Run the automated leak-test suite")
    parser.add_argument("--verify", action="store_true", help="Verify forensic audit ledger integrity")
    parser.add_argument("--tamper", action="store_true", help="Run the interactive forensic tamper demo")
    args = parser.parse_args()

    ensure_prerequisites()

    if args.leaktest:
        subprocess.run([sys.executable, "-m", "leaktest.harness"], cwd=str(PROJECT_ROOT))
        return

    if args.verify:
        subprocess.run([sys.executable, "cli/verify.py", "-v"], cwd=str(PROJECT_ROOT))
        return

    if args.tamper:
        subprocess.run([sys.executable, "cli/verify.py", "--tamper"], cwd=str(PROJECT_ROOT))
        return

    # Default demo runner
    if args.native:
        run_native_demo()
    elif args.docker:
        run_docker_demo()
    else:
        if check_docker_available():
            run_docker_demo()
        else:
            print("[!] Docker engine not active. Falling back to high-fidelity native sandbox runtime...")
            run_native_demo()

if __name__ == "__main__":
    main()
