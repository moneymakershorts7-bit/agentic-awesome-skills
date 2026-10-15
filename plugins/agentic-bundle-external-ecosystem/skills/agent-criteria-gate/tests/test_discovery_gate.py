"""
Unit and Integration Tests for Hierarchical Codebase Discovery Gate
"""

import os
import sys
import tempfile
import unittest

# Ensure module path is accessible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from codebase_extractor import CodebaseExtractor, CodeDeclaration
from discovery_gate import CodebaseDiscoveryGate, DiscoveryResult
from decision_gate import AgentDecisionGate, DecisionAction


class TestCodebaseExtractor(unittest.TestCase):
    def test_extract_python_ast(self):
        code = """
import os
from typing import Optional

class AuthManager:
    \"\"\"Manages user authentication and tokens.\"\"\"
    def __init__(self, secret: str):
        self.secret = secret

    def verify_token(self, token: str) -> bool:
        \"\"\"Verify JWT auth token signature.\"\"\"
        return validate_signature(token, self.secret)

def login(user: str, passw: str) -> str:
    \"\"\"Login handler.\"\"\"
    auth = AuthManager("secret")
    return auth.verify_token("dummy")
"""
        decls = CodebaseExtractor.extract_declarations("src/auth.py", code)
        self.assertGreaterEqual(len(decls), 2)
        class_decl = next((d for d in decls if d.name == "AuthManager"), None)
        func_decl = next((d for d in decls if d.name == "login"), None)

        self.assertIsNotNone(class_decl)
        self.assertEqual(class_decl.kind, "class")
        self.assertIn("Manages user authentication", class_decl.docstring or "")

        self.assertIsNotNone(func_decl)
        self.assertEqual(func_decl.kind, "function")
        self.assertIn("verify_token", func_decl.calls)

    def test_extract_javascript_declarations(self):
        js_code = """
import { sign, verify } from 'jsonwebtoken';

export class TokenService {
    verifyAuthToken(rawToken) {
        return verify(rawToken, "key");
    }
}

export function handleRequest(req, res) {
    const service = new TokenService();
    return service.verifyAuthToken(req.token);
}
"""
        decls = CodebaseExtractor.extract_declarations("src/service.ts", js_code)
        self.assertGreaterEqual(len(decls), 2)
        names = [d.name for d in decls]
        self.assertIn("TokenService", names)
        self.assertIn("handleRequest", names)


class TestCodebaseDiscoveryGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = self.temp_dir.name

        # Create simulated repo structure
        os.makedirs(os.path.join(self.root, "src", "auth"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "src", "billing"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "tests"), exist_ok=True)

        # Auth code
        with open(os.path.join(self.root, "src", "auth", "token.py"), "w") as f:
            f.write("""
def validate_jwt_token(token: str) -> bool:
    \"\"\"Validates JWT token expiration and cryptographic HMAC signature.\"\"\"
    if not token:
        return False
    return True

def extract_bearer_token(header: str) -> str:
    \"\"\"Extracts raw token from Authorization header.\"\"\"
    return header.replace("Bearer ", "")
""")

        # Billing code
        with open(os.path.join(self.root, "src", "billing", "invoice.py"), "w") as f:
            f.write("""
def calculate_vat_tax(amount: float, rate: float = 0.20) -> float:
    \"\"\"Calculates VAT on invoices.\"\"\"
    return amount * rate
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_hierarchical_discovery_finds_relevant_auth_code(self):
        gate = CodebaseDiscoveryGate()
        res = gate.discover(
            query="How are JWT tokens validated and Authorization headers extracted?",
            root_path=self.root
        )

        self.assertIn(res.status, ["complete", "partial"])
        self.assertGreater(len(res.evidence), 0)
        
        # Verify that token.py was matched
        matching_paths = [e.file_path for e in res.evidence]
        self.assertTrue(any("token.py" in p for p in matching_paths))

        # Check untrusted data envelope
        envelope = res.to_data_envelope()
        self.assertEqual(envelope["role"], "data_payload")
        self.assertIn("UNTRUSTED CODEBASE ARTIFACT", envelope["security_notice"])
        self.assertIn("excerpts", envelope)

    def test_navigation_byte_budget_stops_unbounded_search(self):
        # Set tiny budget of 200 bytes
        gate = CodebaseDiscoveryGate(max_navigation_bytes=200, max_files_inspected=1)
        res = gate.discover(query="JWT tokens", root_path=self.root)
        self.assertTrue(res.stats.budget_exhausted)
        self.assertIn(res.status, ["partial", "empty"])

    def test_dynamic_retraction_filters_unrelated_declarations(self):
        gate = CodebaseDiscoveryGate()
        decl_strong = CodeDeclaration(
            kind="function",
            name="verify_auth",
            signature="def verify_auth()",
            docstring="Verify auth",
            start_line=1,
            end_line=10,
            file_path="src/auth.py",
            body_snippet="def verify_auth(): pass",
            relevance_score=0.85
        )
        decl_weak_unrelated = CodeDeclaration(
            kind="function",
            name="unrelated_helper",
            signature="def unrelated_helper()",
            docstring="Unrelated",
            start_line=1,
            end_line=5,
            file_path="src/utils.py",
            body_snippet="def unrelated_helper(): pass",
            calls=["something_else"],
            relevance_score=0.48
        )

        retained, retracted = gate._retract_false_positives([decl_strong, decl_weak_unrelated], query="verify auth")
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].name, "verify_auth")
        self.assertEqual(len(retracted), 1)
        self.assertEqual(retracted[0].name, "unrelated_helper")


class TestAgentDecisionGateIntegration(unittest.TestCase):
    def setUp(self):
        self.gate = AgentDecisionGate()

    def test_code_discovery_prompt_routes_to_discovery(self):
        action, details = self.gate.decide("Where is token authentication validated in the middleware?")
        self.assertEqual(action, DecisionAction.DISCOVER_CODEBASE)
        self.assertEqual(details["route"], "code_discovery")

    def test_revalidate_context_retraction(self):
        evidence = [
            {"signature": "def check_token()", "file_path": "auth.py"},
            {"signature": "def send_email()", "file_path": "mailer.py"}
        ]
        valid, retracted = self.gate.revalidate_context(
            current_evidence=evidence,
            new_observation="The bug is isolated specifically to JWT verification in check_token"
        )
        self.assertGreaterEqual(len(valid), 1)
        self.assertEqual(valid[0]["signature"], "def check_token()")


if __name__ == "__main__":
    unittest.main()
