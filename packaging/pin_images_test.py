#!/usr/bin/env python3
"""pin_images.unknown_to_pins without Docker: what it makes of a pinned image's answers, a failed run included.
    python3 packaging/pin_images_test.py"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pin_images as p  # noqa: E402

INIT = "registry.example/xbt-init:0.1.0-000000000000@sha256:" + "0" * 64
LINK = "registry.example/xbt-hashlink:0.1.0-000000000000@sha256:" + "1" * 64


def done(rc, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


class UnknownToPins(unittest.TestCase):
    def run_with(self, uses, answer):
        p._uses, p._docker = (lambda: uses), answer
        return p.unknown_to_pins()

    def tearDown(self):
        import importlib
        importlib.reload(p)

    def test_a_failed_run_is_a_failure_not_a_pass(self):
        # a pull that failed: docker exits 125 with no report
        bad = self.run_with([("c init", INIT, "init", {"datum"})], lambda *a, **k: done(125, "", "pull access denied"))
        self.assertEqual(len(bad), 1)
        self.assertIn("could not be run", bad[0])

    def test_the_report_decides_whatever_the_exit(self):
        # an init that knows every component: its check still exits 1 (an empty data dir has problems), and that passes
        ok = '{"ok": false, "problems": ["/x/signer missing"]}'
        self.assertEqual(self.run_with([("c init", INIT, "init", {"signer", "datum"})], lambda *a, **k: done(1, ok)), [])
        old = '{"ok": false, "problems": ["unknown component datum", "/x/signer missing"]}'
        bad = self.run_with([("c init", INIT, "init", {"signer", "datum"})], lambda *a, **k: done(1, old))
        self.assertEqual(len(bad), 1)
        self.assertIn("doesn't know the component datum", bad[0])

    def test_a_hashlink_that_cant_be_created_or_read_is_a_failure(self):
        bad = self.run_with([("c renter", LINK, "hashlink", {"--gateway-api"})], lambda *a, **k: done(1, "", "manifest unknown"))
        self.assertIn("could not be pulled or created", bad[0])

        def no_binary(*a, **k):
            return done(0, "abc123\n") if a[0] == "create" else done(1, "", "no such file") if a[0] == "cp" else done(0)
        bad = self.run_with([("c renter", LINK, "hashlink", {"--gateway-api"})], no_binary)
        self.assertIn("has no /usr/bin/xbt-hashlink", bad[0])

    def test_a_hashlink_without_a_flag_is_named(self):
        def binary(*a, **k):
            if a[0] == "cp":
                with open(a[2], "wb") as f:
                    f.write(b"\0--datum-candidates\0renter\0")
                return done(0)
            return done(0, "abc123\n")
        bad = self.run_with([("c renter", LINK, "hashlink", {"--gateway-api", "--datum-candidates"})], binary)
        self.assertEqual(bad, [f"c renter: {LINK} doesn't take --gateway-api"])


if __name__ == "__main__":
    unittest.main()
