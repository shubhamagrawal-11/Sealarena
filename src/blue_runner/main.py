"""
SealArena Blue Runner (Defender)
Uploads encrypted defense rule bundle to Arbiter and monitors aggregate telemetry
without accessing Red team's raw payloads or prompt contents.
"""

import os
import sys
import json
import time
import asyncio
import httpx
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

ARBITER_URL = os.getenv("ARBITER_URL", "http://localhost:8000")
ENCRYPTED_RULES_PATH = PROJECT_ROOT / "configs" / "encrypted_blue_rules.bin"

class BlueRunner:
    def __init__(self, arbiter_url: str = ARBITER_URL):
        self.arbiter_url = arbiter_url
        self.client = httpx.AsyncClient(timeout=10.0)
        self.token_str = ""

    async def get_capability_token(self):
        """Acquires a scoped Blue capability token."""
        resp = await self.client.post(
            f"{self.arbiter_url}/api/v1/auth/token",
            json={
                "tenant_id": "blue",
                "session_id": "blue_defense_ctrl",
                "capabilities": ["deploy_rules", "view_aggregate_telemetry"],
                "forbidden": ["inspect_red_prompts_raw", "intercept_red_traffic"]
            }
        )
        if resp.status_code == 200:
            self.token_str = resp.json()["token_str"]
            print("[+] Blue Runner acquired scoped capability token.")
            return True
        print(f"[-] Blue Runner failed to acquire token: {resp.text}")
        return False

    async def deploy_defense_rules(self):
        """Deploys AES-256-GCM encrypted defense rules to Arbiter guard stage."""
        if not ENCRYPTED_RULES_PATH.exists():
            print(f"[-] Encrypted rules not found at {ENCRYPTED_RULES_PATH}")
            return False

        with open(ENCRYPTED_RULES_PATH, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        resp = await self.client.post(
            f"{self.arbiter_url}/api/v1/blue/rules",
            json=bundle
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"[+] Blue defense rules deployed: version {data['version']}, {data['rules_loaded']} rules active in Arbiter guard.")
            return True
        print(f"[-] Failed to deploy rules: {resp.text}")
        return False

    async def run_loop(self):
        print("[*] Blue Runner starting up...")
        connected = False
        while not connected:
            try:
                h = await self.client.get(f"{self.arbiter_url}/health")
                if h.status_code == 200:
                    connected = True
            except Exception:
                await asyncio.sleep(1)

        await self.get_capability_token()
        await self.deploy_defense_rules()

        print("[*] Blue defense active. Monitoring defense telemetry in non-leak mode...")
        while True:
            await asyncio.sleep(10)

if __name__ == "__main__":
    runner = BlueRunner()
    asyncio.run(runner.run_loop())
