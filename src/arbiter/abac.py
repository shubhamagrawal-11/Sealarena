"""
SealArena Attribute-Based Access Control (ABAC) Policy Engine
Enforces cross-boundary authorization, tenant isolation, and protocol phase progression.
"""

from typing import Dict, Any, Tuple, Optional
from pydantic import BaseModel

class AccessRequest(BaseModel):
    subject_tenant: str
    action: str
    resource: str
    session_id: str
    round_phase: str  # "IDLE", "COMMITTED", "EVALUATING", "REVEALED"
    token_capabilities: list[str]
    token_forbidden: list[str]

class PolicyEngine:
    """Enforces fine-grained ABAC policies for SealArena."""

    def evaluate(self, req: AccessRequest) -> Tuple[bool, str]:
        # 1. Check explicit token-level forbidden actions
        if req.action in req.token_forbidden:
            return False, f"DENY: Action '{req.action}' is explicitly forbidden for tenant '{req.subject_tenant}'"

        # 2. Check capability grant in token
        if req.action not in req.token_capabilities and "*" not in req.token_capabilities:
            return False, f"DENY: Tenant '{req.subject_tenant}' lacks capability '{req.action}'"

        # 3. Protocol phase and boundary-specific rules
        if req.subject_tenant == "red":
            if req.action == "evaluate_prompt":
                if req.round_phase not in ["COMMITTED", "EVALUATING"]:
                    return False, f"DENY: Cannot evaluate prompts before committing payload set. Phase: {req.round_phase}"

            elif req.action == "reveal_payload":
                if req.round_phase not in ["EVALUATING", "READY_FOR_REVEAL"]:
                    return False, f"DENY: Cannot reveal payloads prior to evaluation. Phase: {req.round_phase}"

            elif req.action in ["inspect_rules", "read_blue_verdicts", "query_model_direct"]:
                return False, f"DENY: Tenant 'red' is cryptographically barred from action '{req.action}'"

        elif req.subject_tenant == "blue":
            if req.action == "deploy_rules":
                if req.round_phase in ["EVALUATING"]:
                    return False, "DENY: Cannot modify defense rules during an active evaluation round"

            elif req.action in ["inspect_red_prompts_raw", "intercept_red_traffic"]:
                return False, f"DENY: Tenant 'blue' cannot inspect red payloads prior to reveal phase"

        # 4. Universal boundary isolation rules
        if "cross_tenant_direct" in req.action:
            return False, "DENY: Direct cross-tenant communication is prohibited by micro-segmentation"

        return True, "ALLOW"
