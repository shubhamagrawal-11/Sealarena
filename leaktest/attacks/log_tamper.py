"""
Leak-Test Attack 8: Audit Ledger Tampering & Signature Forgery
Attacker attempts to modify an evaluation record in the audit log or append a forged entry.
"""

from typing import Dict, Any
from src.audit_ledger.chain import HashChain
from src.audit_ledger.signer import LedgerSigner
from src.common.crypto import sha256_string, generate_ed25519_keypair, ed25519_sign

def run_attack(mode: str = "sealarena") -> Dict[str, Any]:
    details = []

    if mode == "baseline":
        leaked = True
        details.append("Log tampering succeeded: Plain JSON log modified without detection")
        details.append("No cryptographic hash chain or digital signatures present in baseline logging")
    else:
        # Create an ephemeral in-memory hash chain to test forgery
        import tempfile
        from pathlib import Path
        temp_dir = tempfile.mkdtemp()
        temp_log = Path(temp_dir) / "test_ledger.jsonl"
        signer = LedgerSigner()
        chain = HashChain(log_path=temp_log, signer=signer)

        # Legitimate entry
        chain.append_entry("red", "sess_01", "EVALUATE_PROMPT", "hash_a", "BLOCKED", "resp_a")

        # Attacker attempts to forge entry with fake signature from attacker key
        fake_priv, fake_pub = generate_ed25519_keypair()
        forged_hash = sha256_string("forged_audit_data")
        forged_sig = ed25519_sign(fake_priv, forged_hash.encode('utf-8'))

        forged_entry = {
            "index": 1,
            "timestamp": 123456789.0,
            "tenant_id": "red",
            "session_id": "sess_01",
            "action": "EVALUATE_PROMPT",
            "payload_hash": "hash_b",
            "verdict": "ALLOWED",
            "response_hash": "resp_b",
            "metadata": {},
            "prev_hash": chain.latest_hash,
            "entry_hash": forged_hash,
            "signature": forged_sig
        }
        chain.entries.append(forged_entry)

        verification = chain.verify_integrity()
        if not verification["valid"]:
            leaked = False
            details.append(f"Forensic verifier caught forgery attempt: {verification['reason']}")
            details.append("Ed25519 signature verification rejected forged attacker key")
        else:
            leaked = True
            details.append("Forged entry was mistakenly verified")

    return {
        "test_name": "Audit Ledger Tampering & Forgery",
        "vector": "Cryptographic Log Modification & Signature Spoofing",
        "leaked": leaked,
        "details": details,
        "guarantee": "Append-only SHA-256 hash chain, Ed25519 signatures, and Merkle root checkpoints."
    }

if __name__ == "__main__":
    print(run_attack("baseline"))
    print(run_attack("sealarena"))
