import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from guardlib import preflight_report, find_secret_findings


class SecretDetectionTests(unittest.TestCase):
    def setUp(self):
        self.cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.allowed_roots = [self.cwd]

    def report(self, command):
        return preflight_report(command, self.cwd, self.allowed_roots)

    def test_bearer_token(self):
        findings = find_secret_findings("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "bearer" for f in findings["findings"]))

    def test_jwt(self):
        findings = find_secret_findings("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "jwt" for f in findings["findings"]))

    def test_aws_access_key(self):
        findings = find_secret_findings("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "aws_access_key" for f in findings["findings"]))

    def test_github_pat(self):
        findings = find_secret_findings("git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/user/repo.git")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "github_pat" for f in findings["findings"]))

    def test_openai_key(self):
        findings = find_secret_findings("sk-abcdefghijklmnopqrstuvwxyz0123456789")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "openai_key" for f in findings["findings"]))

    def test_generic_secret_key_value(self):
        findings = find_secret_findings("api_key=1234567890")
        self.assertEqual(findings["risk"], "high")
        self.assertTrue(any(f["type"] == "generic_secret" for f in findings["findings"]))

    def test_cookie_header(self):
        findings = find_secret_findings("cookie: sessionid=abc123; user=test")
        self.assertEqual(findings["risk"], "high")
        self.assertTrue(any(f["type"] == "cookie" for f in findings["findings"]))

    def test_basic_auth(self):
        findings = find_secret_findings("Authorization: Basic dXNlcjpwYXNzd29yZA==")
        self.assertEqual(findings["risk"], "critical")
        self.assertTrue(any(f["type"] == "basic_auth" for f in findings["findings"]))

    def test_query_string_token(self):
        findings = find_secret_findings("curl https://api.example.com/data?token=abcdef&secret=12345")
        self.assertEqual(findings["risk"], "high")
        self.assertTrue(any(f["type"] == "query_secret" for f in findings["findings"]))

    def test_session_cookie(self):
        findings = find_secret_findings("PHPSESSID=abc123; sessionid=def456; csrf_token=ghj789")
        self.assertEqual(findings["risk"], "high")
        self.assertTrue(any(f["type"] == "session_cookie" for f in findings["findings"]))

    def test_env_file_key_value(self):
        findings = find_secret_findings("SECRET_KEY='mysecret' DATABASE_URL=postgres://user:pass@localhost/db")
        self.assertEqual(findings["risk"], "high")
        self.assertTrue(any(f["type"] == "env_secret" for f in findings["findings"]))

    def test_masking_short(self):
        from guardlib import mask_secret
        self.assertEqual(mask_secret("short"), "***")
        self.assertEqual(mask_secret("12345678"), "***")
        self.assertEqual(mask_secret("123456789"), "1234...6789")
        self.assertEqual(mask_secret("abcdefghijklmnop"), "abcd...mnop")

if __name__ == "__main__":
    unittest.main()