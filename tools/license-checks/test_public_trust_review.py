#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline review boundary cases; synthetic SPKI shapes do not prove production signing capability."""

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

import review_public_trust as review


class PublicTrustReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = review.issuer_module()

    def manifest(self, seed=1):
        # Public SPKI shape only; no private key exists and no signature is claimed.
        def key(kid, purpose, byte):
            der = bytes.fromhex("302a300506032b6570032100") + bytes([byte]) * 32
            return {"kid": kid, "purpose": purpose,
                    "public_key_spki": base64.urlsafe_b64encode(der).rstrip(b"=").decode("ascii")}
        return {"schema_version": 1, "keys": [key("license-a", "license", seed),
                                               key("repair-a", "time_repair", seed + 1)]}

    def model(self, manifest):
        return review.public_model(json.dumps(manifest).encode(), self.issuer)

    def dependencies(self, raw):
        return {"schema_version": 1, "previous_manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "license_kids": ["license-a"], "time_repair_kids": ["repair-a"]}

    def test_fingerprints_cover_full_public_spki_and_preserve_purpose(self):
        manifest = self.manifest()
        rows = self.model(manifest)
        self.assertEqual(["license", "time_repair"], [row["purpose"] for row in rows])
        for row, key in zip(rows, manifest["keys"]):
            self.assertEqual(44, row["spki_bytes"])
            self.assertEqual(hashlib.sha256(base64.urlsafe_b64decode(key["public_key_spki"] + "=")).hexdigest(),
                             row["spki_sha256"])
            self.assertNotIn("public_key_spki", row)

    def test_duplicate_manifest_fields_are_rejected_before_java(self):
        with self.assertRaises(self.issuer.IssuerError):
            review.public_model(b'{"schema_version":1,"schema_version":1,"keys":[]}', self.issuer)

    def test_private_unknown_fields_and_cross_purpose_keys_are_rejected(self):
        for change in ("private", "unknown", "same_public", "duplicate_kid"):
            manifest = self.manifest()
            if change == "private":
                manifest["keys"][0]["private_key"] = "synthetic-private-field"
            elif change == "unknown":
                manifest["certificate_jku"] = "https://unused.invalid"
            elif change == "same_public":
                manifest["keys"][1]["public_key_spki"] = manifest["keys"][0]["public_key_spki"]
            else:
                manifest["keys"][1]["kid"] = manifest["keys"][0]["kid"]
            with self.subTest(change=change), self.assertRaises(self.issuer.IssuerError):
                self.model(manifest)

    def test_retention_requires_explicit_previous_identity_and_both_lists(self):
        manifest = self.manifest()
        raw = json.dumps(manifest).encode()
        required = self.dependencies(raw)
        self.assertEqual(required, review.retention_model(json.dumps(required).encode(), raw,
                                                          self.model(manifest), self.issuer))
        for change in ({"previous_manifest_sha256": "0" * 64}, {"schema_version": True},
                       {"license_kids": ["repair-a"]}, {"time_repair_kids": ["repair-a", "repair-a"]},
                       {"license_kids": [None]}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                review.retention_model(json.dumps({**required, **change}).encode(), raw,
                                       self.model(manifest), self.issuer)

    def test_retained_key_cannot_be_removed_or_changed(self):
        old = self.model(self.manifest())
        for new in ([old[1]], self.model(self.manifest(3))):
            with self.subTest(new=new), self.assertRaises(ValueError):
                review.rotation_model(old, new, self.dependencies(b"unused"))

    def test_unreferenced_removed_key_is_not_claimed_as_verified_retirement(self):
        old = self.model(self.manifest())
        value = review.rotation_model(old, [old[0]], {"license_kids": ["license-a"], "time_repair_kids": []})
        self.assertEqual(["repair-a"], value["removed_keys"])
        self.assertTrue(value["declared_retention_checked"])
        self.assertFalse(value["retention_completeness_verified"])

    def test_cross_purpose_relabel_fails_even_with_a_different_kid(self):
        old = self.model(self.manifest())
        new = [{**old[0], "kid": "new-id", "purpose": "time_repair"}, old[1]]
        with self.assertRaises(ValueError):
            review.rotation_model(old, new, {"license_kids": [], "time_repair_kids": []})

    def test_read_bound_is_enforced_without_trusting_file_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            for content in (b"", b"x" * 65537):
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    review.bounded(path)
            path.write_bytes(b"x" * 65536)
            self.assertEqual(65536, len(review.bounded(path)))

    def test_temurin_release_uses_full_version_instead_of_optional_runtime_field(self):
        review.validate_release_metadata({"JAVA_VERSION": "17.0.4", "FULL_VERSION": "17.0.4+8",
                                          "IMPLEMENTOR": "Eclipse Adoptium"}, "17.0.4+8")

    def test_release_without_vendor_build_field_defers_to_actual_runtime_probe(self):
        review.validate_release_metadata({"JAVA_VERSION": "17.0.4"}, "17.0.4+8")

    def test_release_rejects_wrong_version_or_conflicting_declared_build(self):
        for metadata in ({"JAVA_VERSION": "17.0.2", "FULL_VERSION": "17.0.4+8"},
                         {"JAVA_VERSION": "17.0.4", "FULL_VERSION": "17.0.4+7"},
                         {"JAVA_VERSION": "17.0.4", "JAVA_RUNTIME_VERSION": "17.0.4+7"},
                         {"JAVA_VERSION": "17.0.4", "JAVA_RUNTIME_VERSION": "17.0.4+8",
                          "FULL_VERSION": "17.0.4+7"}):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                review.validate_release_metadata(metadata, "17.0.4+8")

    def loaded_fixture(self, directory):
        # Synthetic class bytes only test the independent source/digest comparison.
        artifacts = {name: directory / (name + ".jar")
                     for name in ("fe", "jackson-core", "jackson-databind", "jackson-annotations")}
        names = {"org.apache.doris.massdb.license." + name: "fe" for name in
                 ("LicenseTrustStore", "LicenseTrustStore$Purpose", "LicenseException",
                  "LicenseText", "LicenseDocument", "LicenseErrorCode", "LicenseVerifier", "LicenseClockRepairVerifier")}
        names.update({"com.fasterxml.jackson.core.JsonFactory": "jackson-core",
                      "com.fasterxml.jackson.databind.ObjectMapper": "jackson-databind"})
        entries = {}
        for artifact in artifacts:
            with zipfile.ZipFile(artifacts[artifact], "w") as archive:
                for name, owner in names.items():
                    if owner == artifact:
                        data = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + name.encode()
                        archive.writestr(name.replace(".", "/") + ".class", data)
                        entries[name] = {"sha256": hashlib.sha256(data).hexdigest(), "major": 52,
                                         "source": str(artifacts[artifact])}
        return artifacts, {"loaded_classes": entries}

    def test_loaded_class_hash_and_actual_artifact_origin_are_independently_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts, result = self.loaded_fixture(Path(temporary))
            jars = {name: path for name, path in artifacts.items() if name != "fe"}
            review.validate_loaded(result, artifacts["fe"], jars)
            target = result["loaded_classes"]["org.apache.doris.massdb.license.LicenseTrustStore"]
            for field, value in (("source", str(artifacts["jackson-core"])), ("sha256", "0" * 64), ("major", 61)):
                original = target[field]
                target[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    review.validate_loaded(result, artifacts["fe"], jars)
                target[field] = original

    def test_failure_output_does_not_reflect_input_or_error_text(self):
        args = ["--manifest", "unused", "--manifest-sha256", "0" * 64, "--java-home", "unused",
                "--expected-java-runtime-version", "17.0.4+8", "--artifact", "unused",
                "--fe-lib", "unused", "--output", "unused"]
        text = io.StringIO()
        with patch.object(review, "review", side_effect=ValueError("sensitive-original-input")), \
                contextlib.redirect_stdout(text):
            self.assertEqual(2, review.main(args))
        self.assertNotIn("sensitive-original-input", text.getvalue())
        self.assertFalse(json.loads(text.getvalue())["production_release_qualified"])

    def test_cancelled_review_cannot_launch_a_child(self):
        with patch.object(review.subprocess, "Popen") as start, self.assertRaises(InterruptedError):
            review.bounded_process(["unused"], [], "cancelled", cancelled=lambda: True)
        start.assert_not_called()

    def test_exiting_child_without_rss_can_await_waitid_without_false_rejection(self):
        for state in ("Z (zombie)", "X (dead)"):
            with self.subTest(state=state):
                review.validate_child_rss("State:\t" + state + "\n", False)
        review.validate_child_rss("State:\tR (running)\n", True)

    def test_live_child_missing_or_excessive_rss_still_fails_closed(self):
        for status in ("State:\tR (running)\n", "State:\tS (sleeping)\n",
                       "State:\tR (running)\nVmRSS:\t786433 kB\n",
                       "State:\tR (running)\nVmRSS:\t100 kB\nVmHWM:\t786433 kB\n"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                review.validate_child_rss(status, False)
        review.validate_child_rss("State:\tR (running)\nVmRSS:\t786432 kB\n", False)

    def test_launch_failure_records_cleanup_and_no_input_text(self):
        receipts = []
        with patch.object(review.subprocess, "Popen", side_effect=OSError("private-input")), \
                self.assertRaises(OSError):
            review.bounded_process(["unused"], receipts, "launch")
        self.assertEqual("OSError", receipts[0]["error_class"])
        self.assertTrue(receipts[0]["owned_leader_reaped"])
        self.assertNotIn("private-input", json.dumps(receipts))

    def test_exited_leader_remains_unreaped_until_its_owned_group_is_cleaned(self):
        child, selector = Mock(), Mock()
        child.pid, child.returncode = 123, None
        selector.get_map.return_value = {}
        order = []
        def group_cleanup(pid, sig):
            self.assertEqual((123, review.signal.SIGKILL), (pid, sig))
            self.assertIsNone(child.returncode)
            order.append("group")
        def reap(timeout):
            order.append("reap")
            child.returncode = 0
            return 0
        child.wait.side_effect = reap
        status = SimpleNamespace(si_code=review.os.CLD_EXITED, si_status=0)
        receipts = []
        with patch.object(review.subprocess, "Popen", return_value=child), \
                patch.object(review.selectors, "DefaultSelector", return_value=selector), \
                patch.object(review.os, "set_blocking"), patch.object(review.os, "waitid", return_value=status), \
                patch.object(review.os, "killpg", side_effect=group_cleanup):
            self.assertEqual(b"", review.bounded_process(["unused"], receipts, "already-exited"))
        self.assertEqual(["group", "reap"], order)
        child.poll.assert_not_called()
        self.assertTrue(receipts[0]["owned_leader_reaped"])

    def test_deadline_failure_still_kills_group_and_reaps_without_reflecting_diagnostics(self):
        child, selector = Mock(), Mock()
        child.pid, child.returncode = 123, None
        selector.get_map.return_value = {"held-pipe": object()}
        def reap(timeout):
            child.returncode = -9
        child.wait.side_effect = reap
        receipts = []
        with patch.object(review.subprocess, "Popen", return_value=child), \
                patch.object(review.selectors, "DefaultSelector", return_value=selector), \
                patch.object(review.os, "set_blocking"), patch.object(review.os, "killpg") as kill, \
                patch.object(review.time, "monotonic", side_effect=[0, 121]), self.assertRaises(ValueError):
            review.bounded_process(["unused"], receipts, "timeout")
        kill.assert_called_once_with(123, review.signal.SIGKILL)
        self.assertEqual(-9, receipts[0]["exit_code"])
        self.assertTrue(receipts[0]["owned_leader_reaped"])


if __name__ == "__main__":
    unittest.main()
