"""
SealArena Red Runner (Attacker)
Executes commit-reveal evaluation rounds, submits benchmark adversarial prompts,
and measures Attack Success Rate (ASR) while strictly isolated from Blue defense state.
"""

import os
import sys
import json
import time
import uuid
import secrets
import asyncio
import httpx
from pathlib import Path
from typing import List, Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.common.crypto import sha256_string

ARBITER_URL = os.getenv("ARBITER_URL", "http://arbiter:8000")
BENCHMARKS_PATH = PROJECT_ROOT / "data" / "benchmarks.json"

class RedRunner:
    def __init__(self, arbiter_url: str = ARBITER_URL):
        self.arbiter_url = arbiter_url
        self.client = httpx.AsyncClient(timeout=15.0)
        self.token_str = ""
        self.session_id = f"red_sess_{uuid.uuid4().hex[:8]}"

    async def acquire_token(self) -> bool:
        """Acquires scoped Red capability token."""
        resp = await self.client.post(
            f"{self.arbiter_url}/api/v1/auth/token",
            json={
                "tenant_id": "red",
                "session_id": self.session_id,
                "capabilities": ["commit_payload", "submit_prompt", "reveal_payload"],
                "forbidden": ["inspect_rules", "read_blue_verdicts", "query_model_direct"],
                "ttl_seconds": 300.0
            }
        )
        if resp.status_code == 200:
            self.token_str = resp.json()["token_str"]
            print(f"[+] Red Runner acquired scoped capability token for session '{self.session_id}'.")
            return True
        print(f"[-] Red Runner failed to acquire token: {resp.text}")
        return False

    async def execute_round(self, loop_continuously: bool = False):
        """Executes full Commit-Reveal evaluation round."""
        with open(BENCHMARKS_PATH, "r", encoding="utf-8") as f:
            benchmarks = json.load(f)

        prompts = [b["prompt"] for b in benchmarks]
        salt = secrets.token_hex(16)

        # 1. Commit Phase
        combined = "".join(prompts) + salt
        commitment_hash = sha256_string(combined)

        print(f"\n[*] [PHASE 1: COMMIT] Registering commitment H(payloads || salt)...")
        print(f"    Commitment Hash: {commitment_hash}")
        print(f"    Payload Count:   {len(prompts)}")

        commit_resp = await self.client.post(
            f"{self.arbiter_url}/api/v1/red/commit",
            json={
                "tenant_id": "red",
                "session_id": self.session_id,
                "commitment_hash": commitment_hash,
                "payload_count": len(prompts),
                "token_str": self.token_str
            }
        )
        if commit_resp.status_code != 200:
            print(f"[-] Commit failed: {commit_resp.text}")
            return

        round_id = commit_resp.json()["round_id"]
        print(f"[+] Commitment bound to ledger. Round ID: {round_id}")

        # 2. Evaluation Phase
        print(f"\n[*] [PHASE 2: EVALUATION] Evaluating {len(prompts)} prompts via Arbiter broker...")
        results = []
        allowed_count = 0
        blocked_count = 0

        for idx, item in enumerate(benchmarks):
            prompt = item["prompt"]
            category = item["category"]

            eval_resp = await self.client.post(
                f"{self.arbiter_url}/api/v1/red/evaluate",
                json={
                    "tenant_id": "red",
                    "session_id": self.session_id,
                    "round_id": round_id,
                    "prompt_index": idx,
                    "prompt": prompt,
                    "token_str": self.token_str
                }
            )

            if eval_resp.status_code in [200, 403]:
                data = eval_resp.json()
                verdict = data["verdict"]
                lat_ms = data["latency_ms"]
                results.append(data)

                if verdict == "ALLOWED":
                    allowed_count += 1
                else:
                    blocked_count += 1

                print(f"  [Prompt #{idx:02d}] {category:<30} -> Verdict: {verdict:<8} | Latency: {lat_ms:.1f}ms")
            else:
                print(f"  [Prompt #{idx:02d}] HTTP Error: {eval_resp.status_code} - {eval_resp.text}")

        total_tested = len(prompts)
        asr = (allowed_count / total_tested) * 100.0 if total_tested > 0 else 0.0
        print(f"\n[*] Evaluation Summary: Total: {total_tested} | Blocked: {blocked_count} | Allowed: {allowed_count} | ASR: {asr:.1f}%")

        # 3. Reveal Phase
        print(f"\n[*] [PHASE 3: REVEAL] Revealing plaintext payloads and salt to prove pre-commitment integrity...")
        reveal_resp = await self.client.post(
            f"{self.arbiter_url}/api/v1/red/reveal",
            json={
                "tenant_id": "red",
                "session_id": self.session_id,
                "round_id": round_id,
                "salt": salt,
                "payloads": prompts,
                "token_str": self.token_str
            }
        )

        if reveal_resp.status_code == 200:
            rev_data = reveal_resp.json()
            if rev_data["commitment_verified"]:
                print(f"[+] Commitment Verified: Hash matches ledger. Red payloads were unmodified during the round.")
            else:
                print(f"[X] Commitment Mismatch! Tampering detected in reveal phase!")
        else:
            print(f"[-] Reveal failed: {reveal_resp.text}")

        if loop_continuously:
            while True:
                await asyncio.sleep(30)
                await self.execute_round(loop_continuously=False)

    async def run(self):
        print("[*] Red Runner initializing...")
        connected = False
        while not connected:
            try:
                h = await self.client.get(f"{self.arbiter_url}/health")
                if h.status_code == 200:
                    connected = True
            except Exception:
                await asyncio.sleep(1)

        await self.acquire_token()
        await self.execute_round(loop_continuously=False)

if __name__ == "__main__":
    runner = RedRunner()
    asyncio.run(runner.run())
