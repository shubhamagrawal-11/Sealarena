#!/usr/bin/env python3
"""
SealArena Blue Defense Rule Encryptor
Encrypts Blue team's defense rules and classifier weights with AES-256-GCM.
The resulting blob is stored in configs/encrypted_blue_rules.bin and can only be
decrypted inside Arbiter's isolated guard stage.
"""

import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.common.crypto import aes_gcm_encrypt
from src.arbiter.guard import GUARD_MASTER_KEY

PLAIN_RULES_PATH = PROJECT_ROOT / "data" / "blue_rules_plain.json"
OUTPUT_BIN_PATH = PROJECT_ROOT / "configs" / "encrypted_blue_rules.bin"

def encrypt_rules():
    print(f"[*] Reading plaintext defense rules from {PLAIN_RULES_PATH}...")
    with open(PLAIN_RULES_PATH, "r", encoding="utf-8") as f:
        data = f.read().encode('utf-8')

    nonce_hex, ciphertext_hex = aes_gcm_encrypt(GUARD_MASTER_KEY, data)

    payload = {
        "tenant_id": "blue",
        "version": "1.0",
        "nonce_hex": nonce_hex,
        "ciphertext_hex": ciphertext_hex,
        "signature": "sig_blue_ed25519_demo"
    }

    OUTPUT_BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_BIN_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[+] Encrypted rules successfully written to {OUTPUT_BIN_PATH}")
    print(f"    Nonce: {nonce_hex}")
    print(f"    Ciphertext Length: {len(ciphertext_hex) // 2} bytes")

if __name__ == "__main__":
    encrypt_rules()
