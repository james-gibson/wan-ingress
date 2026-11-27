#!/usr/bin/env python3
"""The border's verification contract, as a test.

The signature covers method, path, namespace, body digest and timestamp. It
proves *intent*; only the timestamp binds that intent to a moment. Without the
skew window a captured envelope is valid forever, so this file pins both halves:
a fresh envelope verifies, and the same envelope outside the window does not.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import unittest
import urllib.parse

from border_adapter import SKEW_SECONDS, verify

KEY = b"border-key"
PATH_BASE = "/cluster/namespace/session-42/name/42"
NAMESPACE = "session-42"
BODY = b'{"jsonrpc":"2.0","id":1,"method":"adhd.status"}'
POLICY = "cG9saWN5LWlzb3RvcGU"
ROUTE_PATH = "wan-a"


class Headers(dict):
    def get(self, name, default=None):  # http.server's header object shape
        return super().get(name, default)


def envelope(stamp: int) -> Headers:
    digest = hashlib.sha256(BODY).hexdigest()
    escaped = urllib.parse.quote(PATH_BASE, safe="/")
    signature = hmac.new(
        KEY,
        ("POST\n%s\n%s\n%s\n%s\n%s\n%s" % (escaped, NAMESPACE, POLICY, ROUTE_PATH, digest, stamp)).encode(),
        hashlib.sha256,
    ).hexdigest()
    return Headers({
        "X-Lab-Signature": signature,
        "X-Lab-Timestamp": str(stamp),
        "X-Lab-Policy": POLICY,
        "X-Lab-Path": ROUTE_PATH,
    })


class BorderVerifyTest(unittest.TestCase):
    def test_fresh_envelope_verifies(self):
        self.assertTrue(verify(KEY, PATH_BASE, NAMESPACE, BODY, envelope(int(time.time()))))

    def test_replayed_envelope_is_refused_after_the_window(self):
        captured = envelope(int(time.time()) - SKEW_SECONDS - 1)
        # Same signature, same body, same path — only the clock moved.
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY, captured))

    def test_future_envelope_is_refused(self):
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY, envelope(int(time.time()) + SKEW_SECONDS + 1)))

    def test_non_numeric_timestamp_is_refused(self):
        headers = envelope(int(time.time()))
        headers["X-Lab-Timestamp"] = "not-a-number"
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY, headers))

    def test_tampered_body_is_refused(self):
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY + b" ", envelope(int(time.time()))))

    def test_wrong_namespace_is_refused(self):
        self.assertFalse(verify(KEY, PATH_BASE, "session-attacker", BODY, envelope(int(time.time()))))

    def test_a_different_policy_is_refused(self):
        headers = envelope(int(time.time()))
        headers["X-Lab-Policy"] = "b3RoZXItcG9saWN5"
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY, headers))

    def test_a_rewritten_path_is_refused(self):
        headers = envelope(int(time.time()))
        headers["X-Lab-Path"] = "wan-a,wan-b"
        self.assertFalse(verify(KEY, PATH_BASE, NAMESPACE, BODY, headers))


if __name__ == "__main__":
    unittest.main()
