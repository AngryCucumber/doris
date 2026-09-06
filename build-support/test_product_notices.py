# MassDB SQL implementation.
# Licensing decision pending (A02); see dist/source-headers.json.
# This file does not assert an ASF contributor agreement.
"""Exercise distribution checks against the actual UI build and isolated packages."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import socket
import sys
import tarfile
import io

SCRIPT = Path(__file__).with_name("prepare-product-notices.py")
SPEC = importlib.util.spec_from_file_location("product_notices", SCRIPT)
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)
HEADER_SPEC = importlib.util.spec_from_file_location("source_headers", SCRIPT.with_name("check-source-headers.py"))
headers = importlib.util.module_from_spec(HEADER_SPEC)
HEADER_SPEC.loader.exec_module(headers)


class ProductNoticesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="massdb-notice-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ui = self.root / "ui"
        shutil.copytree(notices.ROOT / "ui/dist", self.ui)

    def test_missing_license_is_rejected(self):
        (self.ui / "legal/licenses/LICENSE-LGPL.txt").unlink()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe resource"):
            notices.check_ui(self.ui)

    def test_html_fallback_is_rejected_even_with_matching_hash(self):
        body = b"<html><body>Application shell</body></html>"
        (self.ui / "legal/NOTICE.txt").write_bytes(body)
        path = self.ui / "legal/manifest.json"
        manifest = json.loads(path.read_text())
        next(row for row in manifest["files"] if row["path"] == "legal/NOTICE.txt")["sha256"] = notices.digest(body)
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "HTML fallback"):
            notices.check_ui(self.ui)

    def test_altered_repository_notice_is_rejected(self):
        file = self.ui / "legal/MODIFICATIONS.txt"
        file.write_text(file.read_text() + "\nUnreviewed attribution change\n")
        path = self.ui / "legal/manifest.json"
        manifest = json.loads(path.read_text())
        next(row for row in manifest["files"] if row["path"] == "legal/MODIFICATIONS.txt")["sha256"] = notices.digest(file.read_bytes())
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Stale or omitted repository notice"):
            notices.check_ui(self.ui)

    def test_custom_ui_with_unlisted_asset_is_rejected(self):
        (self.ui / "unlisted.js").write_text("window.unlisted = true;")
        with self.assertRaisesRegex(ValueError, "UI assets differ"):
            notices.check_ui(self.ui)

    def test_empty_component_inventory_is_rejected(self):
        path = self.ui / "legal/manifest.json"
        manifest = json.loads(path.read_text())
        manifest["components"] = []
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Missing bundled component"):
            notices.check_ui(self.ui)

    def test_omitted_component_entry_is_rejected(self):
        path = self.ui / "legal/manifest.json"
        manifest = json.loads(path.read_text())
        manifest["components"].pop()
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Component inventory differs"):
            notices.check_ui(self.ui)

    def test_stale_product_metadata_is_rejected(self):
        path = self.ui / "legal/manifest.json"
        original = path.read_text()
        for key, value in (("mariadb", {"version": "3.0.4"}),
                           ("companyEn", "Incorrect company"),
                           ("copyrightYears", "1900"),
                           ("upstream", {"sourceCommit": "0" * 40})):
            with self.subTest(key=key):
                manifest = json.loads(original)
                manifest["metadata"][key] = value
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "Stale product notices: " + key):
                    notices.check_ui(self.ui)

    def test_static_resources_survive_jar_packaging(self):
        jar = self.root / "doris-fe.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for file in self.ui.rglob("*"):
                if file.is_file():
                    archive.write(file, "static/" + file.relative_to(self.ui).as_posix())
        result = subprocess.run(["python3", str(SCRIPT), "--check-fe-jar", str(jar)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fe_materials_are_separate_and_bound_to_the_binary(self):
        data = notices.metadata()
        data["mariadb"]["jarSha256"] = notices.digest(b"test JDBC binary")
        data["mariadb"]["sourceSha256"] = notices.digest(b"test corresponding source")
        source = self.root / "jdbc-source.tar.gz"
        source.write_bytes(b"test corresponding source")
        fe = self.root / "fe"
        (fe / "lib").mkdir(parents=True)
        jar = fe / "lib" / f"mariadb-java-client-{data['mariadb']['version']}.jar"
        jar.write_bytes(b"test JDBC binary")
        with patch.object(notices, "metadata", return_value=data), patch.dict(os.environ, {"MASSDB_MARIADB_SOURCE_ARCHIVE": str(source)}):
            notices.install_fe(fe)
            self.assertTrue((fe / "legal/FE-SOURCE-ACCESS.txt").is_file())
            self.assertEqual(len(list((fe / "legal/sources").glob("*.tar.gz"))), 1)
            self.assertFalse(any((self.ui / "legal").glob("*.tar.gz")))
            jar.write_bytes(b"changed JDBC binary")
            with self.assertRaisesRegex(ValueError, "differs from reviewed artifact"):
                notices.install_fe(fe)

    def test_vendored_source_assembly_uses_no_network(self):
        data = notices.metadata()
        data["mariadb"]["jarSha256"] = notices.digest(b"test JDBC binary")
        fe = self.root / "offline-fe"
        (fe / "lib").mkdir(parents=True)
        (fe / "lib/mariadb-java-client-3.0.9.jar").write_bytes(b"test JDBC binary")
        with patch.dict(os.environ), patch.object(notices, "metadata", return_value=data), \
                patch.object(socket, "create_connection", side_effect=AssertionError("Unexpected network access")):
            os.environ.pop("MASSDB_MARIADB_SOURCE_ARCHIVE", None)
            notices.install_fe(fe)
        source = fe / "legal/sources/mariadb-connector-j-3.0.9.tar.gz"
        self.assertEqual(notices.digest(source.read_bytes()), data["mariadb"]["sourceSha256"])

    def test_missing_source_reports_local_recovery(self):
        with patch.dict(os.environ, {"MASSDB_MARIADB_SOURCE_ARCHIVE": str(self.root / "missing.tar.gz")}):
            with self.assertRaisesRegex(ValueError, "MASSDB_MARIADB_SOURCE_ARCHIVE.*does not download"):
                notices.mariadb_source(notices.metadata())

    def test_source_archive_provenance_without_git(self):
        with patch.object(notices, "ROOT", self.root), patch.dict(os.environ), \
                patch.object(notices.subprocess, "check_output", side_effect=AssertionError("Git should not run")):
            os.environ.pop("MASSDB_SOURCE_COMMIT", None)
            self.assertEqual(notices.source_identity(), {"sourceCommit": "unknown", "sourceModified": None})
            (self.root / "dist").mkdir()
            info = self.root / "dist/source-version.json"
            info.write_text(json.dumps({"sourceCommit": "a" * 40, "sourceModified": False}))
            self.assertEqual(notices.source_identity(), {"sourceCommit": "a" * 40, "sourceModified": False})
            info.write_text(json.dumps({"sourceCommit": "$Format:%H$", "sourceModified": False}))
            self.assertEqual(notices.source_identity()["sourceCommit"], "unknown")
            os.environ["MASSDB_SOURCE_COMMIT"] = "b" * 40
            self.assertEqual(notices.source_identity()["sourceCommit"], "b" * 40)

    def test_release_requires_clean_known_source(self):
        for commit, modified, valid in [("a" * 40, False, True), ("a" * 40, True, False),
                                        ("a" * 40, None, False), ("unknown", False, False)]:
            with self.subTest(commit=commit, modified=modified), patch.object(
                    notices, "source_identity", return_value={"sourceCommit": commit, "sourceModified": modified}):
                if valid:
                    notices.check_release_provenance()
                else:
                    with self.assertRaisesRegex(ValueError, "Release requires"):
                        notices.check_release_provenance()

    def test_source_identity_detects_changes_outside_fe_be(self):
        checkout = self.root / "source-checkout"
        (checkout / "cloud").mkdir(parents=True)
        (checkout / "cloud/config.txt").write_text("committed\n")
        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Source fixture",
                                            "-c", "user.email=fixture@example.invalid",
                                            "-c", "core.hooksPath=/dev/null", *args], cwd=checkout)
        git("init", "-q")
        git("add", "cloud/config.txt")
        git("commit", "-qm", "source fixture")
        with patch.object(notices, "ROOT", checkout), patch.dict(os.environ):
            os.environ.pop("MASSDB_SOURCE_COMMIT", None)
            self.assertFalse(notices.source_identity()["sourceModified"])
            (checkout / "cloud/config.txt").write_text("modified\n")
            self.assertTrue(notices.source_identity()["sourceModified"])
            (checkout / "cloud/config.txt").write_text("committed\n")
            (checkout / "release-input.txt").write_text("untracked\n")
            self.assertTrue(notices.source_identity()["sourceModified"])

    def test_java_inventory_includes_nested_jars_and_original_notices(self):
        package = self.root / "package"
        (package / "be").mkdir(parents=True)
        (package / "fe").mkdir()
        child = io.BytesIO()
        with zipfile.ZipFile(child, "w") as jar:
            jar.writestr("META-INF/LICENSE", "Original library license text\n")
            jar.writestr("META-INF/maven/example/library/pom.properties", "groupId=example\nartifactId=library\nversion=1.0\n")
            jar.writestr("META-INF/maven/example/library/pom.xml", "<project><licenses><license><name>Fixture License</name></license></licenses></project>")
        outer = package / "be/cdc-client.jar"
        with zipfile.ZipFile(outer, "w") as jar:
            jar.writestr("BOOT-INF/lib/library.jar", child.getvalue())
        shutil.copyfile(outer, package / "fe/copied.jar")
        destination = self.root / "inventory"
        with patch.object(socket, "create_connection", side_effect=AssertionError("Unexpected network access")):
            notices.inventory_java_package(package, destination)
        inventory = json.loads((destination / "java-inventory.json").read_text())
        self.assertEqual(inventory["outerJarCounts"], {"be": 1, "fe": 1})
        self.assertEqual(inventory["uniqueArchives"], 2)
        self.assertEqual(len(inventory["occurrences"]), 4)
        self.assertFalse(inventory["licenseReviewComplete"])
        item = next(row for row in inventory["archives"] if row["coordinates"])
        self.assertEqual(item["declaredLicenses"][0]["name"], "Fixture License")
        self.assertEqual((destination / item["notices"][0]["file"]).read_text(), "Original library license text\n")
        bom = json.loads((destination / "java-sbom.cdx.json").read_text())
        self.assertEqual(len(bom["components"]), 2)
        self.assertTrue(any(row["dependsOn"] for row in bom["dependencies"]))

    def test_old_python_reports_requirement(self):
        command = "import sys, runpy; sys.version_info = (3, 8); runpy.run_path(sys.argv[1], run_name='__main__')"
        result = subprocess.run([sys.executable, "-c", command, str(SCRIPT)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Python 3.9+", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_node_npm_version_bounds(self):
        for node, npm, valid in [("v22.23.2", "10.9.9", True), ("v16.3.0", "10.9.9", False),
                                 ("v22.23.1", "10.9.9", False), ("v24.0.0", "10.9.9", False),
                                 ("v22.23.2", "11.0.0", False)]:
            with self.subTest(node=node, npm=npm), \
                    patch.object(notices.subprocess, "check_output", side_effect=[node, npm]):
                if valid:
                    notices.check_ui_toolchain()
                else:
                    with self.assertRaisesRegex(ValueError, "UI build requires"):
                        notices.check_ui_toolchain()

    def test_git_archive_exports_source_identity(self):
        archive_root = self.root / "archive"
        (archive_root / "dist").mkdir(parents=True)
        for name in (".gitattributes", "dist/source-version.json"):
            shutil.copyfile(notices.ROOT / name, archive_root / name)
        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Archive fixture",
                                            "-c", "user.email=fixture@example.invalid",
                                            "-c", "core.hooksPath=/dev/null", *args], cwd=archive_root)
        git("init", "-q")
        git("add", ".gitattributes", "dist/source-version.json")
        git("commit", "-qm", "archive fixture")
        commit = git("rev-parse", "HEAD").decode().strip()
        with tarfile.open(fileobj=io.BytesIO(git("archive", "HEAD"))) as archive:
            source = json.load(archive.extractfile("dist/source-version.json"))
        self.assertEqual(source, {"sourceCommit": commit, "sourceModified": False})

    def test_build_preflight_skips_node_for_custom_or_headless_ui(self):
        root = self.root / "preflight"
        root.mkdir()
        for name in ("build-support/prepare-product-notices.py", "dist/product-provenance.json",
                     "dist/sources/mariadb-connector-j-3.0.9.tar.gz", "ui/package.json",
                     "gensrc/script/gen_build_version.sh", "fe/pom.xml"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(notices.ROOT / name, target)
        # Exercise the real argument parsing and preflight, stopping before database compilation.
        build = (notices.ROOT / "build.sh").read_text().split("# build thirdparty libraries if necessary.")[0]
        (root / "build.sh").write_text(build + "\nexit 0\n")
        (root / "env.sh").write_text('export MASSDB_NOTICE_PYTHON="' + sys.executable + '"\n')
        binaries = root / "bin"
        binaries.mkdir()
        marker = root / "node-called"
        for name, version in (("node", "v16.3.0"), ("npm", "7.15.1")):
            executable = binaries / name
            executable.write_text('#!/bin/sh\necho called >> "' + str(marker) + '"\necho ' + version + '\n')
            executable.chmod(0o755)
        for extra, expected in [({}, 1), ({"CUSTOM_UI_DIST": "/prebuilt"}, 0),
                                ({"DISABLE_BUILD_UI": "ON"}, 0)]:
            with self.subTest(extra=extra):
                env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"])
                for key in ("CUSTOM_UI_DIST", "DISABLE_BUILD_UI", "MASSDB_SOURCE_COMMIT", "MASSDB_MARIADB_SOURCE_ARCHIVE"):
                    env.pop(key, None)
                env.update(extra)
                marker.unlink(missing_ok=True)
                result = subprocess.run(["bash", "build.sh", "--fe"], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(marker.exists(), not bool(extra))

    def header_fixture(self):
        policy = json.loads((notices.ROOT / "dist/source-headers.json").read_text())
        files = policy["pending"] + policy["apache"] + list(policy["modifiedUpstream"])
        files += ["dist/source-headers.json", "dist/product-provenance.json", ".licenserc.yaml", ".gitattributes",
                  "dist/headers/apache-2.0.txt", "fe/check/checkstyle/checkstyle.xml"]
        root = self.root / "headers"
        for name in set(files):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(notices.ROOT / name, target)
        return root, policy

    def test_pending_headers_allow_review_but_block_release(self):
        root, policy = self.header_fixture()
        headers.check(root)
        with self.assertRaisesRegex(ValueError, "Release blocked: licensing decision A02"):
            headers.check(root, release=True)
        path = root / policy["pending"][0]
        path.write_text("// Header removed\n")
        with self.assertRaisesRegex(ValueError, "Missing or changed pending-license header"):
            headers.check(root)

    def test_header_checks_respect_explicit_source_archive_exclusions(self):
        root, policy = self.header_fixture()
        name = next(name for name in policy["modifiedUpstream"] if name.startswith("regression-test/"))
        (root / name).unlink()
        self.assertEqual(headers.check(root)[2], len(policy["modifiedUpstream"]) - 1)
        (root / ".git").mkdir()
        with self.assertRaises(FileNotFoundError):
            headers.check(root)

    def test_original_header_and_upstream_notice_are_required(self):
        root, policy = self.header_fixture()
        name, record = next(iter(policy["modifiedUpstream"].items()))
        path = root / name
        original = path.read_text()
        for before, error in [("Licensed to the Apache Software Foundation", "Original upstream header"),
                              (record["notice"], "Missing modification/source notice")]:
            with self.subTest(before=before):
                path.write_text(original.replace(before, "Removed", 1))
                with self.assertRaisesRegex(ValueError, error):
                    headers.check(root)
        path.write_text(original)

    def test_plan_spdx_and_full_apache_headers(self):
        root, policy = self.header_fixture()
        data = json.loads((root / "dist/product-provenance.json").read_text())
        path = root / next(name for name in policy["apache"] if name.endswith(".java"))
        prefix = "// Copyright (c) 2026\n// " + data["companyZh"] + "\n// " + data["companyEn"] + "\n"
        full = path.read_text()
        for text in [full, prefix + full, prefix + "// SPDX-License-Identifier: Apache-2.0\nclass Example {}\n"]:
            path.write_text(text)
            headers.check(root)
        path.write_text(prefix + "class Example {}\n")
        with self.assertRaisesRegex(ValueError, "Invalid independently authored Apache header"):
            headers.check(root)
        path.write_text(full)
        future = root / "fe/example/src/main/java/example/massdb/NewFile.java"
        future.parent.mkdir(parents=True)
        future.write_text(full)
        with self.assertRaisesRegex(ValueError, "Register independent Java source"):
            headers.check(root)


if __name__ == "__main__":
    unittest.main()
