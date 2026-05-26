#!/usr/bin/env python3
"""
AuthGuard Pro v4.1 — Vulnerability Chaining System
Passes credentials, tokens, and session state between modules.
Enables multi-step exploit chains like real attackers use.
"""

import re, json, base64, urllib.parse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ChainCredential:
    """A credential or token discovered during scanning."""
    type: str  # "jwt", "session_cookie", "api_key", "basic_auth", "form_creds"
    value: str
    source_module: str
    source_endpoint: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if token/credential is likely expired."""
        if self.type == "jwt" and self.metadata.get("exp"):
            try:
                exp_ts = self.metadata["exp"]
                return datetime.utcnow().timestamp() > exp_ts
            except:
                pass
        return False


@dataclass
class ChainState:
    """Shared state that persists across scan modules."""
    credentials: List[ChainCredential] = field(default_factory=list)
    active_session: Dict[str, str] = field(default_factory=dict)
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_apis: List[str] = field(default_factory=list)
    user_contexts: Dict[str, Dict] = field(default_factory=dict)
    pivot_points: List[Dict] = field(default_factory=list)

    def add_credential(self, cred: ChainCredential):
        """Add a credential, avoiding duplicates."""
        for existing in self.credentials:
            if existing.type == cred.type and existing.value == cred.value:
                return
        self.credentials.append(cred)

    def get_credentials(self, cred_type: str = None,
                        source_module: str = None) -> List[ChainCredential]:
        """Get credentials filtered by type and/or source."""
        result = self.credentials
        if cred_type:
            result = [c for c in result if c.type == cred_type]
        if source_module:
            result = [c for c in result if c.source_module == source_module]
        return [c for c in result if not c.is_expired()]

    def get_best_auth_header(self) -> Optional[str]:
        """Get the best available authorization header."""
        for cred in self.credentials:
            if cred.type == "jwt" and cred.metadata.get("is_admin"):
                return f"Bearer {cred.value}"
        for cred in self.credentials:
            if cred.type == "jwt":
                return f"Bearer {cred.value}"
        for cred in self.credentials:
            if cred.type == "api_key":
                return f"Api-Key {cred.value}"
        return None

    def get_session_cookies(self) -> Dict[str, str]:
        """Get all active session cookies."""
        return self.active_session


class ExploitChain:
    """
    Manages multi-step exploit chains.
    Each chain is a sequence of operations that build on previous results.
    """

    def __init__(self, http_session, chain_state: ChainState):
        self.http = http_session
        self.state = chain_state
        self.steps = []
        self.success = False
        self.impact = "none"

    def add_step(self, name: str, description: str,
                 execute_fn, verify_fn) -> bool:
        """
        Add and execute a chain step.
        execute_fn: function that performs the action
        verify_fn: function that verifies the step succeeded
        Returns True if step succeeded.
        """
        try:
            result = execute_fn(self.http, self.state)
            verified = verify_fn(result)

            self.steps.append({
                "name": name,
                "description": description,
                "success": verified,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })

            if verified:
                if isinstance(result, dict):
                    if "credential" in result:
                        self.state.add_credential(result["credential"])
                    if "session" in result:
                        self.state.active_session.update(result["session"])
                    if "endpoints" in result:
                        self.state.discovered_endpoints.extend(result["endpoints"])
                return True
            return False

        except Exception as e:
            self.steps.append({
                "name": name,
                "description": description,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            return False

    def get_chain_report(self) -> Dict:
        """Generate a report of the entire chain."""
        return {
            "success": self.success,
            "impact": self.impact,
            "steps_executed": len(self.steps),
            "steps": self.steps,
            "credentials_discovered": len(self.state.credentials),
            "endpoints_discovered": len(self.state.discovered_endpoints)
        }


CHAIN_TEMPLATES = {
    "jwt_to_admin": {
        "name": "Token Exposure -> Admin Surface Check",
        "description": "Use observed (not forged) authentication context to check for unintended admin surface exposure",
        "steps": [
            ("extract_token_exposure", "Identify exposed tokens in responses or JS"),
            ("probe_admin_surface", "Check admin endpoints for unintended access"),
            ("verify_data_exposure", "Verify any sensitive data exposure from accessible endpoints")
        ]
    },
    "auth_to_idor": {
        "name": "Authentication -> IDOR Chain",
        "description": "If an authenticated session is legitimately established, verify object-level access controls",
        "steps": [
            ("find_login", "Discover login endpoint"),
            ("establish_session", "Maintain authenticated session"),
            ("discover_api", "Find API endpoints in authenticated state"),
            ("test_idor", "Test for insecure direct object references")
        ]
    },
    "sqli_to_rce": {
        "name": "Injection Signal -> Evidence Collection",
        "description": "Collect evidence of injection indicators without attempting exploitation",
        "steps": [
            ("confirm_sqli", "Confirm SQL injection vulnerability"),
            ("verify_impact", "Confirm sensitive data exposure")
        ]
    },
    "recon_to_exploit": {
        "name": "Deep Recon -> Targeted Verification",
        "description": "Parse JS files, discover endpoints, and verify misconfigurations with captured responses",
        "steps": [
            ("crawl_js", "Download and parse JavaScript files"),
            ("extract_endpoints", "Find API endpoints in JS code"),
            ("fuzz_params", "Discover hidden parameters"),
            ("verify_surface", "Verify discovered endpoints for exposed metadata or misconfigurations")
        ]
    }
}


class ChainEngine:
    """Main engine that orchestrates exploit chains."""

    def __init__(self, http_session, target: str):
        self.http = http_session
        self.target = target
        self.state = ChainState()
        self.chains_executed = []
        self.active_chains = []

    def run_chain(self, template_name: str,
                  step_functions: Dict[str, tuple]) -> ExploitChain:
        """
        Execute a chain template with provided step functions.
        step_functions: dict of step_name -> (execute_fn, verify_fn)
        """
        template = CHAIN_TEMPLATES.get(template_name)
        if not template:
            raise ValueError(f"Unknown chain template: {template_name}")

        chain = ExploitChain(self.http, self.state)

        for step_key, step_desc in template["steps"]:
            if step_key not in step_functions:
                continue
            execute_fn, verify_fn = step_functions[step_key]
            success = chain.add_step(step_key, step_desc, execute_fn, verify_fn)

            if not success and step_key in ["confirm_sqli"]:
                break

        if any(s["name"] in ["verify_data_exposure", "test_idor"] and s["success"] for s in chain.steps):
            chain.impact = "high"
        elif any(s["success"] for s in chain.steps):
            chain.impact = "medium"

        chain.success = any(s["success"] for s in chain.steps)
        self.chains_executed.append(chain)
        return chain

    def get_all_credentials(self) -> List[ChainCredential]:
        """Get all discovered credentials."""
        return self.state.credentials

    def get_auth_context(self) -> Dict:
        """Get current authentication context for modules."""
        return {
            "headers": {},
            "cookies": self.state.active_session,
            "bearer_token": None
        }
