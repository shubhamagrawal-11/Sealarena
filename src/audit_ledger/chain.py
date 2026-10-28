"""
SealArena Hash Chain Manager
Implements append-only, tamper-evident hash chaining with Ed25519 signatures.
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from src.common.crypto import (
    canonical_json_bytes,
    sha256_hash,
    sha256_string,
    ed25519_verify,
    import_ed25519_public_hex
)
from src.audit_ledger.signer import LedgerSigner

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
LEDGER_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "audit_ledger.jsonl"

class HashChain:
    """Manages append-only hash-chained audit log with Ed25519 digital signatures."""

    def __init__(self, log_path: Path = LEDGER_LOG_PATH, signer: Optional[LedgerSigner] = None):
        self.log_path = log_path
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.log_path = Path("/tmp/audit_ledger.jsonl")
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer or LedgerSigner()
        self.entries: List[Dict[str, Any]] = []
        self._load_existing_log()

    def _load_existing_log(self):
        if self.log_path.exists():
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self.entries.append(json.loads(line))

    @property
    def latest_hash(self) -> str:
        if self.entries:
            return self.entries[-1]["entry_hash"]
        return GENESIS_PREV_HASH

    def append_entry(
        self,
        tenant_id: str,
        session_id: str,
        action: str,
        payload_hash: str,
        verdict: str,
        response_hash: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates a signed, hash-chained audit block and persists it to disk."""
        index = len(self.entries)
        now = time.time()
        prev_hash = self.latest_hash

        core_data = {
            "index": index,
            "timestamp": now,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "action": action,
            "payload_hash": payload_hash,
            "verdict": verdict,
            "response_hash": response_hash,
            "metadata": metadata or {},
            "prev_hash": prev_hash
        }

        # Calculate H_i = SHA256(prev_hash || canonical_json(core_data))
        combined_bytes = prev_hash.encode('utf-8') + canonical_json_bytes(core_data)
        entry_hash = sha256_hash(combined_bytes)

        # Sign entry_hash with Ed25519 private key
        signature = self.signer.sign(entry_hash.encode('utf-8'))

        full_record = dict(core_data)
        full_record["entry_hash"] = entry_hash
        full_record["signature"] = signature

        self.entries.append(full_record)

        # Append directly to JSONL log file
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(full_record) + "\n")
        except OSError:
            self.log_path = Path("/tmp/audit_ledger.jsonl")
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(full_record) + "\n")

        return full_record

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Replays the full hash chain from genesis, verifies all signatures,
        and checks hash continuity.
        """
        if not self.entries:
            return {"valid": True, "count": 0, "message": "Ledger is empty"}

        expected_prev = GENESIS_PREV_HASH
        pub_key = import_ed25519_public_hex(self.signer.get_public_key_hex())

        for idx, entry in enumerate(self.entries):
            # 1. Index check
            if entry.get("index") != idx:
                return {
                    "valid": False,
                    "failed_index": idx,
                    "reason": f"Index mismatch: expected {idx}, got {entry.get('index')}"
                }

            # 2. Previous hash link check
            if entry.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "failed_index": idx,
                    "reason": f"Hash chain broken at block {idx}: prev_hash mismatch. Expected {expected_prev}, got {entry.get('prev_hash')}"
                }

            # 3. Recompute hash
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
            combined_bytes = expected_prev.encode('utf-8') + canonical_json_bytes(core_data)
            recomputed_hash = sha256_hash(combined_bytes)

            if recomputed_hash != entry.get("entry_hash"):
                return {
                    "valid": False,
                    "failed_index": idx,
                    "reason": f"Content tampering detected at block {idx}! Hash mismatch: expected {entry.get('entry_hash')}, computed {recomputed_hash}"
                }

            # 4. Verify Ed25519 signature
            sig_valid = ed25519_verify(pub_key, entry["entry_hash"].encode('utf-8'), entry["signature"])
            if not sig_valid:
                return {
                    "valid": False,
                    "failed_index": idx,
                    "reason": f"Cryptographic signature invalid at block {idx}!"
                }

            expected_prev = entry["entry_hash"]

        return {
            "valid": True,
            "count": len(self.entries),
            "latest_hash": expected_prev,
            "message": f"Successfully verified {len(self.entries)} audit blocks. Hash chain and Ed25519 signatures 100% valid."
        }
