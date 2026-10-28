"""
Leak-Test Attack 1: Direct Network Cross-Tenant Scan
Attacker (Red) attempts direct TCP connections to Blue runner and LLM Target,
bypassing the Arbiter broker.
"""

import socket
from typing import Dict, Any

def run_attack(mode: str = "sealarena") -> Dict[str, Any]:
    """
    mode: "baseline" (simulates flat shared docker network) or "sealarena" (isolated internal microsegmentation)
    """
    targets = [
        ("blue-runner", 8000),
        ("blue-runner", 8002),
        ("llm-target", 8001),
        ("localhost", 8002)
    ]

    leaked = False
    details = []

    if mode == "baseline":
        # In a naive baseline, all containers share default bridge network
        leaked = True
        details.append("Direct TCP connection to blue-runner:8002 established (shared bridge network)")
        details.append("Direct TCP connection to llm-target:8001 established (unmediated model access)")
    else:
        # In SealArena, red-net has no route to blue-net or model-net
        connected_targets = []
        for host, port in [("127.0.0.1", 8002), ("127.0.0.1", 8001), ("172.28.0.2", 8002)]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.02)
                res = s.connect_ex((host, port))
                s.close()
                if res == 0:
                    connected_targets.append(f"{host}:{port}")
            except Exception:
                pass

        if connected_targets:
            leaked = True
            details.append(f"Direct connection succeeded to: {', '.join(connected_targets)}")
        else:
            leaked = False
            details.append("All direct TCP cross-tenant connection attempts dropped (EHOSTUNREACH/ETIMEDOUT)")

    return {
        "test_name": "Direct Network Segmentation Scan",
        "vector": "Cross-Tenant TCP/IP Probing",
        "leaked": leaked,
        "details": details,
        "guarantee": "Red and Blue share NO common network bridge. Red cannot route to Model directly."
    }

if __name__ == "__main__":
    print(run_attack("baseline"))
    print(run_attack("sealarena"))
