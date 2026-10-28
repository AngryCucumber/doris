#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Unit tests for the Python runtime build and check scripts on synthetic inputs."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("build_python_runtime", "build-python-runtime.py")
check = load("check_python_runtime", "check-python-runtime.py")
CONFIG = json.loads((HERE / "python-runtime.json").read_text(encoding="utf-8"))


def make_elf(path, align, needed=(), versions=None, machine=183):
    """Minimal 64-bit LE shared object: one PT_LOAD, a PT_DYNAMIC with DT_NEEDED and DT_VERNEED."""
    versions = versions or {}
    strings = bytearray(b"\0")

    def text(value):
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    needed_offsets = [text(name) for name in needed]
    verneed = bytearray()
    libraries = list(versions.items())
    for index, (library, names) in enumerate(libraries):
        aux = bytearray()
        for position, name in enumerate(names):
            step = 16 if position < len(names) - 1 else 0
            aux += struct.pack("<IHHII", 0, 0, 2 + position, text(name), step)
        following = 16 + len(aux) if index < len(libraries) - 1 else 0
        verneed += struct.pack("<HHIII", 1, len(names), text(library), 16, following) + aux
    header, program = 64, 56
    phoff, dynamic_offset = header, header + 2 * program
    entries = [(1, offset) for offset in needed_offsets]
    dynamic_size = 16 * (len(entries) + 4)
    strtab_offset = dynamic_offset + dynamic_size
    verneed_offset = strtab_offset + len(strings)
    entries += [(5, strtab_offset), (0x6ffffffe, verneed_offset), (0x6fffffff, len(libraries)), (0, 0)]
    body = b"".join(struct.pack("<qQ", tag, value) for tag, value in entries) + bytes(strings) + bytes(verneed)
    size = dynamic_offset + len(body)
    identity = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    data = identity + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, phoff, 0, 0, header, program, 2, 64, 0, 0)
    data += struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, align)
    data += struct.pack("<IIQQQQQQ", 2, 6, dynamic_offset, dynamic_offset, dynamic_offset, dynamic_size,
                        dynamic_size, 8)
    path.write_bytes(data + body)


class BuildScriptTest(unittest.TestCase):
    def test_platform_tags_stop_at_target_glibc(self):
        tags = build.platform_tags("aarch64", "2.28")
        self.assertEqual(tags[0], "manylinux_2_28_aarch64")
        self.assertIn("manylinux_2_17_aarch64", tags)
        self.assertIn("manylinux2014_aarch64", tags)
        self.assertNotIn("manylinux_2_29_aarch64", tags)
        self.assertIn("manylinux1_x86_64", build.platform_tags("x86_64", "2.17"))
        with self.assertRaises(SystemExit):
            build.platform_tags("aarch64", "2.12")

    def test_requirement_names_are_canonical(self):
        self.assertEqual(build.requirement_name("PyYAML>=6"), "pyyaml")
        self.assertEqual(build.requirement_name("python_dateutil[extra]==2.9 ; python_version>'3'"), "python-dateutil")

    def test_pack_is_deterministic_and_keeps_relative_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "python-runtime"
            (root / "envs/python3.12.15/bin").mkdir(parents=True)
            (root / "envs/python3.12.15/bin/python3.12").write_text("#!/bin/sh\n")
            os.symlink("python3.12", root / "envs/python3.12.15/bin/python")
            first, second = Path(temp) / "a.tar.gz", Path(temp) / "b.tar.gz"
            build.pack(root, first, 1700000000)
            os.utime(root / "envs/python3.12.15/bin/python3.12", (1, 1))
            build.pack(root, second, 1700000000)
            self.assertEqual(build.digest(first), build.digest(second))
            self.assertTrue((Path(temp) / "a.tar.gz.sha256").read_text().startswith(build.digest(first)))

    def test_find_leaks_reports_build_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "clean.txt").write_text("nothing here")
            (root / "leaky.py").write_text(f"PREFIX = '{temp}/stage'")
            self.assertEqual(build.find_leaks(root, temp.encode()), ["leaky.py"])

    def test_rewrite_scripts_replaces_absolute_shebangs(self):
        with tempfile.TemporaryDirectory() as temp:
            env_dir = Path(temp) / "envs/python3.12.15"
            (env_dir / "bin").mkdir(parents=True)
            short, long = env_dir / "bin/f2py", env_dir / "bin/normalizer"
            short.write_text(f"#!{env_dir}/bin/python3.12\nimport sys\n")
            long.write_text(f"#!/bin/sh\n'''exec' {env_dir}/bin/python \"$0\" \"$@\"\n' '''\nimport os\n")
            untouched = env_dir / "bin/tool"
            untouched.write_text("#!/usr/bin/env python3\n")
            site = env_dir / "lib/python3.12/site-packages"
            (site / "demo-1.0.dist-info").mkdir(parents=True)
            (site / "demo-1.0.dist-info/RECORD").write_bytes(
                b"../../../bin/f2py,sha256=stale,10\r\ndemo/__init__.py,sha256=keep,0\r\n")
            build.update_records(site, build.rewrite_scripts(env_dir, "python3.12"))
            expected = build.TRAMPOLINE.format(python="python3.12")
            record = (site / "demo-1.0.dist-info/RECORD").read_bytes().decode()
            data = short.read_bytes()
            fresh = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            self.assertEqual(record, f"../../../bin/f2py,sha256={fresh},{len(data)}\r\n"
                                     "demo/__init__.py,sha256=keep,0\r\n")
            self.assertEqual(short.read_text(), expected + "import sys\n")
            self.assertEqual(long.read_text(), expected + "import os\n")
            self.assertEqual(untouched.read_text(), "#!/usr/bin/env python3\n")
            self.assertEqual(build.find_leaks(env_dir, str(env_dir).encode()), [])


class ElfCheckTest(unittest.TestCase):
    def target(self, **changes):
        target = {"glibc": "2.17", "glibcxx": None, "cxxabi": None, "minLoadAlign": 0x10000}
        target.update(changes)
        return target

    def test_parse_elf_reads_needed_libraries_and_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libdemo.so"
            make_elf(path, 0x10000, ["libc.so.6", "libstdc++.so.6"],
                     {"libc.so.6": ["GLIBC_2.17", "GLIBC_2.28"], "libstdc++.so.6": ["GLIBCXX_3.4.25"]})
            info = check.parse_elf(path)
            self.assertEqual(info["machine"], 183)
            self.assertEqual(info["aligns"], [0x10000])
            self.assertEqual(info["needed"], ["libc.so.6", "libstdc++.so.6"])
            self.assertEqual(info["versions"]["libc.so.6"], {"GLIBC_2.17", "GLIBC_2.28"})

    def test_page_alignment_glibc_and_machine_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_elf(root / "ok.so", 0x10000, ["libc.so.6"], {"libc.so.6": ["GLIBC_2.17"]})
            make_elf(root / "small-pages.so", 0x1000, ["libc.so.6"], {"libc.so.6": ["GLIBC_2.17"]})
            make_elf(root / "new-glibc.so", 0x10000, ["libc.so.6"], {"libc.so.6": ["GLIBC_2.34"]})
            make_elf(root / "x86.so", 0x10000, machine=62)
            report = check.Report()
            check.check_elf(root, "aarch64", self.target(), report)
            errors = {finding["message"].split(" ", 1)[1]: finding["items"]
                      for finding in report.findings if finding["level"] == "error"}
            self.assertEqual(len(errors), 3)
            self.assertTrue(any(item.startswith("small-pages.so") for items in errors.values() for item in items))
            self.assertTrue(any(item.startswith("new-glibc.so (GLIBC_2.34)") for items in errors.values()
                                for item in items))
            self.assertIn(["x86.so"], errors.values())
            self.assertEqual(report.facts["newestSymbolVersions"]["GLIBC"], "2.34")

    def test_glibcxx_limit_and_unusual_system_libraries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_elf(root / "ext.so", 0x10000, ["libstdc++.so.6", "libz.so.1", "libbundled.so.1"],
                     {"libstdc++.so.6": ["GLIBCXX_3.4.29"]})
            make_elf(root / "libbundled.so.1", 0x10000)
            (root / "lib").mkdir()
            make_elf(root / "lib/libpython3.12.so.1.0", 0x10000)
            make_elf(root / "lib/libpython3.so", 0x10000, ["$ORIGIN/libpython3.12.so.1.0", "$ORIGIN/libgone.so"])
            report = check.Report()
            check.check_elf(root, "aarch64", self.target(glibcxx="3.4.25"), report)
            levels = {(finding["level"], finding["check"]): finding for finding in report.findings}
            self.assertIn("GLIBCXX_3.4.25", levels[("error", "elf")]["message"])
            self.assertEqual(levels[("warning", "elf")]["items"],
                             ["$ORIGIN/libgone.so (needed by 1 files, e.g. lib/libpython3.so)",
                              "libz.so.1 (needed by 1 files, e.g. ext.so)"])
            self.assertEqual(report.facts["systemLibraries"], ["$ORIGIN/libgone.so", "libstdc++.so.6", "libz.so.1"])

    def test_cxxabi_limit_catches_what_glibcxx_alone_misses(self):
        """On CentOS 7 (libstdc++ 4.8.5) numpy 2.5 fails on CXXABI_1.3.9 while its GLIBCXX need is old enough."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_elf(root / "numpy-like.so", 0x10000, ["libstdc++.so.6"],
                     {"libstdc++.so.6": ["GLIBCXX_3.4.19", "CXXABI_1.3.9"]})
            make_elf(root / "arrow-like.so", 0x10000, ["libstdc++.so.6"],
                     {"libstdc++.so.6": ["GLIBCXX_3.4.21", "CXXABI_1.3.7"]})

            def errors(**limits):
                report = check.Report()
                check.check_elf(root, "aarch64", self.target(**limits), report)
                return {finding["message"]: finding["items"] for finding in report.findings
                        if finding["level"] == "error"}, report

            only_glibcxx, _ = errors(glibcxx="3.4.19")
            self.assertEqual(list(only_glibcxx.values()), [["arrow-like.so (GLIBCXX_3.4.21)"]])
            both, report = errors(glibcxx="3.4.19", cxxabi="1.3.7")
            self.assertEqual(both, {
                "1 ELF files need a libstdc++ newer than GLIBCXX_3.4.19": ["arrow-like.so (GLIBCXX_3.4.21)"],
                "1 ELF files need a libstdc++ newer than CXXABI_1.3.7": ["numpy-like.so (CXXABI_1.3.9)"]})
            info = next(finding["message"] for finding in report.findings if finding["level"] == "info")
            self.assertEqual(info, "Checked 2 ELF files: newest GLIBC_-, GLIBCXX_3.4.21, CXXABI_1.3.9")


class LayoutAndLicenseTest(unittest.TestCase):
    def test_broken_env_and_symlinks_are_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "python-runtime"
            good = root / "envs/python3.12.15"
            (good / "bin").mkdir(parents=True)
            (good / "lib/python3.12/site-packages").mkdir(parents=True)
            (good / "bin/python").write_text("#!/bin/sh\necho 'Python 3.12.15'\n")
            (good / "bin/python").chmod(0o755)
            (root / "envs/leftover").mkdir()
            os.symlink("/usr/bin/env", good / "bin/absolute")
            os.symlink("missing", good / "bin/broken")
            os.symlink("../../../../outside", good / "bin/escaping")
            (Path(temp) / "outside").write_text("x")
            report = check.Report()
            manifest = {"env": {"name": "python3.12.15"}, "python": {"version": "3.12.15"}}
            selected = check.check_layout(root, manifest, check.clean_env(temp), report)
            check.check_symlinks(root, report)
            self.assertEqual(selected[0], "3.12.15")
            messages = [finding["message"] for finding in report.findings if finding["level"] == "error"]
            self.assertTrue(any("envs/leftover/bin/python" in message for message in messages))
            self.assertEqual(sum("symlinks" in message for message in messages), 3)

    def test_license_verdicts(self):
        policy = CONFIG["licensePolicy"]

        def verdict(expression=None, classifiers=(), text=None, name="demo"):
            distribution = {"name": name, "expression": expression, "classifiers": list(classifiers),
                            "license": text}
            return check.license_verdict(distribution, policy, CONFIG.get("licenseOverrides", {}))[0]

        self.assertEqual(verdict("MIT"), "allow")
        self.assertEqual(verdict("BSD-3-Clause AND MIT"), "allow")
        self.assertEqual(verdict("GPL-3.0-only"), "deny")
        self.assertEqual(verdict("AGPL-3.0-or-later"), "deny")
        self.assertEqual(verdict("LGPL-2.1-or-later"), "review")
        self.assertEqual(verdict("MIT OR GPL-2.0-only"), "allow")
        self.assertEqual(verdict("MIT AND GPL-2.0-only"), "deny")
        self.assertNotEqual(verdict("GPL-3.0-or-later WITH GCC-exception-3.1"), "deny")
        self.assertEqual(verdict(classifiers=["GNU Lesser General Public License v3 (LGPLv3)"]), "review")
        self.assertEqual(verdict(classifiers=["GNU General Public License v2 (GPLv2)"]), "deny")
        self.assertEqual(verdict(classifiers=["MIT License", "GNU General Public License v2 (GPLv2)"]), "review")
        self.assertEqual(verdict(text="Apache License 2.0"), "allow")
        self.assertEqual(verdict(text="UNKNOWN"), "unknown")

    def test_module_names_from_record(self):
        distribution = {"topLevel": [], "record": [
            ["yaml/__init__.py", "", ""], ["_yaml/__init__.py", "", ""], ["six.py", "", ""],
            ["_cffi_backend.cpython-312-aarch64-linux-gnu.so", "", ""], ["demo.libs/libx.so", "", ""],
            ["demo-1.0.dist-info/METADATA", "", ""], ["../../../bin/tool", "", ""], ["demo.pth", "", ""]]}
        self.assertEqual(check.module_names(distribution), ["_cffi_backend", "_yaml", "six", "yaml"])
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            (site / "xxhash").mkdir()
            (site / "six.py").write_text("")
            (site / "_cffi_backend.cpython-312-aarch64-linux-gnu.so").write_text("")
            stale = {"topLevel": ["_xxhash", "xxhash"], "record": []}
            self.assertEqual(check.module_names(stale, site), ["xxhash"])
            self.assertEqual(check.module_names(distribution, site), ["_cffi_backend", "six"])


if __name__ == "__main__":
    unittest.main()
