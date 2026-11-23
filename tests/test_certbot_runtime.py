"""Fail-closed checks for the offline Certbot payload."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import certbot_runtime
import security_policy


class CertbotPayloadTests(unittest.TestCase):
    def test_untrusted_bytes_cannot_create_a_runtime(self):
        with tempfile.TemporaryDirectory() as scratch:
            source, runtime = Path(scratch) / "input", Path(scratch) / "runtime"
            source.mkdir()
            names = ("requirements.lock", certbot_runtime.CERTBOT_PIP_WHEEL, *certbot_runtime.CERTBOT_LIBRARIES)
            for name in names:
                (source / name).write_bytes(name.encode())
            (source / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n" for name in names))
            certbot_runtime.verify_certbot_payload(source)
            run = mock.Mock(side_effect=OSError("fixture failure"))
            with self.assertRaisesRegex(OSError, "fixture failure"):
                certbot_runtime.install_certbot_runtime(source, runtime, run)
            self.assertFalse(runtime.exists())
            run.reset_mock()
            (source / "libssl.so.3").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                certbot_runtime.install_certbot_runtime(source, runtime, run)
            self.assertFalse(runtime.exists())
            run.assert_not_called()
            (source / "extra.whl").touch()
            with self.assertRaisesRegex(ValueError, "unlisted"):
                certbot_runtime.verify_certbot_payload(source)

    def test_policy_requires_exact_approved_digest_and_freshness(self):
        approved = ("fixture", "a" * 64)
        old = (security_policy.SECURITY_BLOCKED_BUNDLE_VERSION, security_policy.SECURITY_BLOCKED_BUNDLE_SHA256)
        evaluate = security_policy.evaluate_pinned_release
        with mock.patch.object(security_policy, "SECURITY_APPROVED_BUNDLE", approved):
            self.assertEqual(evaluate(*approved, today="2026-11-23")["status"], "PASS")
            self.assertEqual(evaluate("fixture", "b" * 64, today="2026-11-23")["status"], "UNKNOWN")
            self.assertEqual(evaluate(*approved, today="2026-12-23")["status"], "STALE")
            self.assertEqual(evaluate(*old, today="2026-11-23")["status"], "BLOCKED")
