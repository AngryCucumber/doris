# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Test a built meta_tool with JAVA_HOME configured.

Run: python3 -m unittest discover -s build-support -p test_meta_tool_runtime.py
MASSDB_META_TOOL optionally selects a binary instead of output/be/lib/meta_tool.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class MetaToolRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ.get("MASSDB_META_TOOL", ROOT / "output/be/lib/meta_tool")).resolve()
        if not cls.binary.is_file():
            raise unittest.SkipTest("Build meta_tool first or set MASSDB_META_TOOL")

    def test_tablet_schema_round_trip_in_separate_processes(self):
        records = ROOT / ".build-records"
        records.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="meta-tool-test-", dir=records) as directory:
            root = Path(directory)
            storage = root / "storage"
            storage.mkdir()
            metadata = {
                "table_id": 1,
                "partition_id": 2,
                "tablet_id": 41501,
                "schema_hash": 415,
                "tablet_state": "PB_RUNNING",
                "tablet_uid": {"hi": 1, "lo": 2},
                "schema": {
                    "keys_type": "DUP_KEYS",
                    "num_short_key_columns": 1,
                    "next_column_unique_id": 2,
                    "column": [
                        {"unique_id": 0, "name": "id", "type": "INT", "is_key": True,
                         "is_nullable": False, "length": 4, "index_length": 4},
                        {"unique_id": 1, "name": "payload", "type": "VARCHAR", "is_key": False,
                         "is_nullable": True, "length": 64, "index_length": 20, "aggregation": "NONE"},
                    ],
                },
            }
            fixture = root / "tablet.json"
            fixture.write_text(json.dumps(metadata), encoding="utf-8")
            env = dict(os.environ, DORIS_HOME=str(root))
            if env.get("JAVA_HOME"):
                env["LD_LIBRARY_PATH"] = str(Path(env["JAVA_HOME"]) / "lib/server") + os.pathsep + env.get(
                    "LD_LIBRARY_PATH", "")

            def run(*arguments):
                process = subprocess.run([str(self.binary), "--root_path=" + str(storage), *arguments],
                                         cwd=root, env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
                return process.stdout

            self.assertIn("load meta successfully", run("--operation=load_meta", "--json_meta_path=" + str(fixture)))
            actual = json.loads(run("--operation=get_meta", "--tablet_id=41501", "--schema_hash=415"))
            self.assertEqual(int(actual["tablet_id"]), metadata["tablet_id"])
            self.assertEqual(actual["schema"]["keys_type"], "DUP_KEYS")
            self.assertEqual([(c["name"], c["type"], c["is_nullable"]) for c in actual["schema"]["column"]],
                             [("id", "INT", False), ("payload", "VARCHAR", True)])


if __name__ == "__main__":
    unittest.main()
