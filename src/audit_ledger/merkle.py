"""
SealArena Merkle Checkpointing Service
Groups audit entries into cryptographic epochs and seals them with signed Merkle roots.
"""

import time
import json
import uuid
from typing import List, Dict, Any, Optional
from src.common.crypto import MerkleTree, canonical_json_bytes
from src.audit_ledger.signer import LedgerSigner

class MerkleCheckpointManager:
    """Computes and seals Merkle root checkpoints periodically."""

    def __init__(self, signer: LedgerSigner, batch_size: int = 5):
        self.signer = signer
        self.batch_size = batch_size
        self.checkpoints: List[Dict[str, Any]] = []
        self.last_checkpointed_idx = -1

    def maybe_create_checkpoint(self, entries: List[Dict[str, Any]], force: bool = False) -> Optional[Dict[str, Any]]:
        """Creates a signed Merkle checkpoint if batch size is reached or forced."""
        total_entries = len(entries)
        uncheckpointed = total_entries - (self.last_checkpointed_idx + 1)

        if uncheckpointed < self.batch_size and not force:
            return None

        if total_entries == 0 or uncheckpointed <= 0:
            return None

        start_idx = self.last_checkpointed_idx + 1
        end_idx = total_entries - 1

        batch_hashes = [e["entry_hash"] for e in entries[start_idx:end_idx + 1]]
        tree = MerkleTree(batch_hashes)
        merkle_root = tree.root

        now = time.time()
        ckpt_data = {
            "checkpoint_id": f"ckpt_{uuid.uuid4().hex[:8]}",
            "timestamp": now,
            "start_index": start_idx,
            "end_index": end_idx,
            "entry_count": len(batch_hashes),
            "merkle_root": merkle_root
        }

        # Sign checkpoint with Ed25519
        sig = self.signer.sign(canonical_json_bytes(ckpt_data))
        ckpt_data["signature"] = sig

        self.checkpoints.append(ckpt_data)
        self.last_checkpointed_idx = end_idx
        return ckpt_data
