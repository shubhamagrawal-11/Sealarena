"""
SealArena Cryptographic Core
Implements Ed25519 signatures, Merkle trees, AES-256-GCM, and SHA-256 canonical hashing.
"""

import os
import json
import hashlib
from typing import List, Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# --- Canonical JSON & Hashing ---

def canonical_json_bytes(data: Any) -> bytes:
    """Produces deterministic UTF-8 JSON bytes with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sha256_hash(data: bytes) -> str:
    """Computes hex-encoded SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()

def sha256_string(s: str) -> str:
    """Computes hex-encoded SHA-256 digest of a string."""
    return sha256_hash(s.encode('utf-8'))

# --- Ed25519 Signatures ---

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 private/public keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> str:
    """Signs a message using Ed25519 and returns hex signature."""
    sig = private_key.sign(message)
    return sig.hex()

def ed25519_verify(public_key: ed25519.Ed25519PublicKey, message: bytes, signature_hex: str) -> bool:
    """Verifies an Ed25519 signature."""
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False

def export_ed25519_public_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    """Exports raw 32-byte public key as hex."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return raw.hex()

def import_ed25519_public_hex(pub_hex: str) -> ed25519.Ed25519PublicKey:
    """Imports Ed25519 public key from hex string."""
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

# --- AES-256-GCM Encryption (for Blue defense rules) ---

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[str, str]:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns (nonce_hex, ciphertext_hex).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Standard 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce.hex(), ct.hex()

def aes_gcm_decrypt(key: bytes, nonce_hex: str, ciphertext_hex: str, associated_data: bytes = b"") -> bytes:
    """Decrypts ciphertext with AES-256-GCM."""
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ct = bytes.fromhex(ciphertext_hex)
    return aesgcm.decrypt(nonce, ct, associated_data)

# --- Merkle Tree Implementation ---

class MerkleTree:
    """
    Binary Merkle Tree for periodic forensic checkpointing.
    """
    def __init__(self, leaf_hashes: List[str]):
        self.leaf_hashes = leaf_hashes if leaf_hashes else ["0" * 64]
        self.tree = self._build_tree(self.leaf_hashes)

    def _build_tree(self, leaves: List[str]) -> List[List[str]]:
        current_layer = list(leaves)
        tree = [current_layer]

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                combined = (left + right).encode('utf-8')
                parent_hash = sha256_hash(combined)
                next_layer.append(parent_hash)
            tree.append(next_layer)
            current_layer = next_layer

        return tree

    @property
    def root(self) -> str:
        """Returns the Merkle root hash."""
        return self.tree[-1][0]

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """Generates Merkle inclusion proof for a leaf at given index."""
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError("Leaf index out of bounds")

        proof = []
        idx = index
        for layer in self.tree[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(layer):
                proof.append({"position": "left" if is_right else "right", "hash": layer[sibling_idx]})
            else:
                proof.append({"position": "right", "hash": layer[idx]})
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """Verifies inclusion proof against expected Merkle root."""
        current = leaf_hash
        for step in proof:
            sibling = step["hash"]
            pos = step["position"]
            if pos == "left":
                combined = (sibling + current).encode('utf-8')
            else:
                combined = (current + sibling).encode('utf-8')
            current = sha256_hash(combined)
        return current.lower() == expected_root.lower()
