"""Readiness publication regression; no external server/credential/network is needed."""
import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("owned_kubernetes_verifier", Path(__file__).with_name("owned_kubernetes_verifier.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

class ReadyPublication(unittest.TestCase):
    def publication(self, previous):
        with tempfile.TemporaryDirectory(prefix="owned-kube-ready-test-") as temporary:
            path = Path(temporary) / "ready"
            if previous is not None:
                verifier.publish_ready(path, previous)
            entered, release = threading.Event(), threading.Event()
            failures = []
            real_fsync = os.fsync
            def gate(descriptor):
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("test reader did not release readiness publication")
                real_fsync(descriptor)
            def publish():
                try:
                    verifier.publish_ready(path, 32123)
                except BaseException as error:
                    failures.append(error)
            with mock.patch.object(verifier.os, "fsync", gate):
                writer = threading.Thread(target=publish)
                writer.start()
                try:
                    self.assertTrue(entered.wait(3))
                    if previous is None:
                        self.assertFalse(path.exists(), "reader must not see an empty ready file")
                    else:
                        self.assertEqual(path.read_text(), str(previous))
                    pending = list(path.parent.glob(".ready-*"))
                    self.assertEqual(len(pending), 1)
                    self.assertEqual(pending[0].stat().st_mode & 0o777, 0o600)
                finally:
                    release.set()
                    writer.join(3)
            self.assertFalse(writer.is_alive())
            self.assertFalse(failures)
            self.assertEqual(path.read_text(), "32123")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(path.parent.glob(".ready-*")))

    def test_initial_reader_cannot_observe_create_before_write(self):
        self.publication(None)

    def test_replacement_reader_retains_previous_complete_port(self):
        self.publication(12345)

    def test_failed_replace_keeps_previous_port_and_cleans_pending(self):
        with tempfile.TemporaryDirectory(prefix="owned-kube-ready-failure-") as temporary:
            path = Path(temporary) / "ready"
            verifier.publish_ready(path, 12345)
            with mock.patch.object(verifier.os, "replace", side_effect=OSError("controlled publication failure")):
                with self.assertRaises(OSError):
                    verifier.publish_ready(path, 32123)
            self.assertEqual(path.read_text(), "12345")
            self.assertFalse(list(path.parent.glob(".ready-*")))

    def test_invalid_port_never_creates_ready_or_pending_file(self):
        with tempfile.TemporaryDirectory(prefix="owned-kube-ready-invalid-") as temporary:
            path = Path(temporary) / "ready"
            for port in (0, -1, 65536, True, "443", 443.0):
                with self.assertRaises(ValueError):
                    verifier.publish_ready(path, port)
            self.assertFalse(list(path.parent.iterdir()))

if __name__ == "__main__":
    unittest.main()
