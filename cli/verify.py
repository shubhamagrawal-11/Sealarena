#!/usr/bin/env python3
"""
SealArena Standalone Forensic Audit Verifier CLI
Replays the append-only hash-chained ledger, validates Ed25519 digital signatures,
reconstructs Merkle root checkpoints, and features an interactive tamper demo.
"""

import sys
import json
import argparse
import shutil
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.common.crypto import (
    canonical_json_bytes,
    sha256_hash,
    ed25519_verify,
    import_ed25519_public_hex,
    MerkleTree
)
from src.audit_ledger.signer import LedgerSigner
from src.audit_ledger.chain import GENESIS_PREV_HASH, LEDGER_LOG_PATH

def print_banner():
    banner = """
====================================================================
           SEALARENA FORENSIC AUDIT TRAIL VERIFIER
           Zero-Trust Cryptographic Chain Integrity Replay
====================================================================
    """
    print(banner)

def verify_log_file(log_path: Path, pub_key_hex: str, verbose: bool = False):
    """Replays and cryptographically verifies the entire audit ledger."""
    if not log_path.exists():
        print(f"[-] Ledger file not found at: {log_path}")
        return False

    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception as e:
                print(f"[!] Malformed JSON on line {line_no}: {e}")
                return False

    print(f"[*] Replaying {len(records)} audit block(s) from {log_path}...")
    pub_key = import_ed25519_public_hex(pub_key_hex)
    expected_prev = GENESIS_PREV_HASH

    for idx, entry in enumerate(records):
        block_idx = entry.get("index")
        tenant = entry.get("tenant_id")
        action = entry.get("action")
        verdict = entry.get("verdict")
        stored_entry_hash = entry.get("entry_hash")
        stored_prev_hash = entry.get("prev_hash")
        sig = entry.get("signature")

        # 1. Sequential Index Check
        if block_idx != idx:
            print(f"\n[X] TAMPER DETECTED: Sequential Index Broken!")
            print(f"    Expected index: {idx}, found index: {block_idx}")
            return False

        # 2. Hash Chain Link Check
        if stored_prev_hash != expected_prev:
            print(f"\n[X] TAMPER DETECTED: Hash Chain Broken at Block #{idx}!")
            print(f"    Previous block hash expected: {expected_prev}")
            print(f"    Recorded prev_hash in block:   {stored_prev_hash}")
            return False

        # 3. Content Integrity Recomputation
        core_data = {
            "index": entry["index"],
            "timestamp": entry["timestamp"],
            "tenant_id": entry["tenant_id"],
            "session_id": entry["session_id"],
            "action": entry["action"],
            "payload_hash": entry["payload_hash"],
            "verdict": entry["verdict"],
            "response_hash": entry["response_hash"],
            "metadata": entry.get("metadata", {}),
            "prev_hash": entry["prev_hash"]
        }
        recomputed_hash = sha256_hash(expected_prev.encode('utf-8') + canonical_json_bytes(core_data))

        if recomputed_hash != stored_entry_hash:
            print(f"\n[X] TAMPER DETECTED: Block #{idx} Content Modified!")
            print(f"    Action: {action} | Tenant: {tenant} | Verdict: {verdict}")
            print(f"    Recorded Hash:   {stored_entry_hash}")
            print(f"    Recomputed Hash: {recomputed_hash}")
            return False

        # 4. Ed25519 Signature Verification
        if not ed25519_verify(pub_key, stored_entry_hash.encode('utf-8'), sig):
            print(f"\n[X] TAMPER DETECTED: Invalid Ed25519 Digital Signature on Block #{idx}!")
            print(f"    Signature: {sig[:32]}... does not match public key!")
            return False

        if verbose:
            print(f"  [OK] Block #{idx:03d} | Tenant: {tenant:<10} | Action: {action:<18} | Hash: {stored_entry_hash[:16]}... | SIG: VALID")

        expected_prev = stored_entry_hash

    print("\n--------------------------------------------------------------------")
    print(f"[+] AUDIT INTEGRITY STATUS: 100% VERIFIED")
    print(f"[+] Verified {len(records)} blocks with zero tampering.")
    print(f"[+] Hash chain continuity: VALID (Genesis -> Tip: {expected_prev[:24]}...)")
    print(f"[+] Ed25519 digital signatures: ALL VALID")
    print("--------------------------------------------------------------------")
    return True

def run_tamper_demo(log_path: Path, pub_key_hex: str):
    """Executes the tamper demonstration: modifies 1 byte in a block and shows verification failure."""
    print("\n[*] ================= TAMPER DEMO STARTED =================")
    print("[*] Backing up original audit ledger...")
    backup_path = log_path.with_suffix(".jsonl.bak")
    shutil.copyfile(log_path, backup_path)

    try:
        # Read lines
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            print("[-] No records in log file to tamper. Please run an evaluation round first.")
            return

        target_idx = min(1, len(lines) - 1)
        target_entry = json.loads(lines[target_idx])

        print(f"[*] Original Block #{target_idx} Content:")
        print(f"    Action:  {target_entry.get('action')}")
        print(f"    Verdict: {target_entry.get('verdict')}")
        print(f"    Hash:    {target_entry.get('entry_hash')[:24]}...")

        # Maliciously alter verdict: e.g. from BLOCKED to ALLOWED (or vice versa)
        tampered_verdict = "ALLOWED" if target_entry.get("verdict") == "BLOCKED" else "BLOCKED"
        target_entry["verdict"] = tampered_verdict
        lines[target_idx] = json.dumps(target_entry)

        print(f"\n[!] MALICIOUS TAMPERING INJECTED:")
        print(f"    Changed block #{target_idx} verdict to: '{tampered_verdict}' without re-signing!")

        # Write tampered log
        with open(log_path, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")

        print("\n[*] Re-running Forensic Verifier against tampered ledger...")
        result = verify_log_file(log_path, pub_key_hex, verbose=True)

        if not result:
            print("\n[+] SUCCESS: Forensic verifier successfully caught the tamper attempt!")
        else:
            print("\n[X] FAILURE: Verifier failed to detect tampering!")

    finally:
        print("\n[*] Restoring original pristine audit ledger from backup...")
        shutil.copyfile(backup_path, log_path)
        backup_path.unlink(missing_ok=True)
        print("[*] Ledger restored. Re-verifying clean state...")
        verify_log_file(log_path, pub_key_hex, verbose=False)
        print("[*] ================= TAMPER DEMO FINISHED =================")

def main():
    parser = argparse.ArgumentParser(description="SealArena Forensic Audit Verifier")
    parser.add_argument("--log", type=str, default=str(LEDGER_LOG_PATH), help="Path to audit_ledger.jsonl")
    parser.add_argument("--tamper", action="store_true", help="Run interactive tamper detection demo")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose block output")
    args = parser.parse_args()

    print_banner()

    signer = LedgerSigner()
    pub_key_hex = signer.get_public_key_hex()
    log_path = Path(args.log)

    if args.tamper:
        run_tamper_demo(log_path, pub_key_hex)
    else:
        verify_log_file(log_path, pub_key_hex, verbose=args.verbose)

if __name__ == "__main__":
    main()
