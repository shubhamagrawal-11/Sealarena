"""
SealArena Ledger Cryptographic Signer
Signs every audit block with an Ed25519 private key.
"""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from src.common.crypto import (
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    export_ed25519_public_hex,
    import_ed25519_public_hex
)

KEY_PATH = Path(__file__).resolve().parent.parent.parent / "certs" / "ledger_ed25519.pem"

class LedgerSigner:
    def __init__(self, key_path: Path = KEY_PATH):
        self.key_path = key_path
        self.priv_key, self.pub_key = self._load_or_generate_key()

    def _load_or_generate_key(self):
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            with open(self.key_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
                return priv, priv.public_key()
        else:
            priv, pub = generate_ed25519_keypair()
            with open(self.key_path, "wb") as f:
                f.write(
                    priv.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            return priv, pub

    def sign(self, message: bytes) -> str:
        return ed25519_sign(self.priv_key, message)

    def get_public_key_hex(self) -> str:
        return export_ed25519_public_hex(self.pub_key)
