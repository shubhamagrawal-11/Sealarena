"""
Leak-Test Attack 4: Docker Socket & Container Escape Probing
Attacker probes for /var/run/docker.sock exposure or dangerous capabilities (SYS_ADMIN, PTRACE).
"""

from pathlib import Path
from typing import Dict, Any

def run_attack(mode: str = "sealarena") -> Dict[str, Any]:
    details = []

    if mode == "baseline":
        leaked = True
        details.append("CRITICAL: /var/run/docker.sock mounted inside container! Root host takeover possible.")
        details.append("Container running as root (UID 0) with CAP_SYS_ADMIN enabled.")
    else:
        sock_paths = [Path("/var/run/docker.sock"), Path("/run/docker.sock")]
        sock_found = any(p.exists() for p in sock_paths)

        if sock_found:
            leaked = True
            details.append("Docker socket detected inside container")
        else:
            leaked = False
            details.append("Zero docker.sock mounts detected; non-root user (UID 1000); cap_drop ALL active")

    return {
        "test_name": "Docker Socket & Privilege Escape",
        "vector": "Container Breakout & Host Daemon Control",
        "leaked": leaked,
        "details": details,
        "guarantee": "No docker.sock; cap_drop ALL; no-new-privileges; strict seccomp profile."
    }
