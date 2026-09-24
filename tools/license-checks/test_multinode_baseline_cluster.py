#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Offline ownership, resource and membership oracles; never launches a namespace or service."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import multinode_baseline_cluster as cluster


def profile():
    return {"nodes": {name: ({"cpus": [0, 1], "heap_mib": 1024} if name.startswith("fe") else
                            {"cpus": [2, 3], "memory_mib": 2048, "jvm_heap_mib": 256})
                      for name in cluster.NAMES}, "reserve_mib": 4096, "allow_existing_host_limits": True}


def membership():
    nodes = [{"name": name, "component": name[:2], "ip": "10.254.23." + str(11 + index)}
             for index, name in enumerate(cluster.NAMES)]
    frontends = [{"Host": node["ip"], "Role": "FOLLOWER", "IsMaster": str(index == 0).lower(),
                  "ClusterId": "1201", "Join": "true", "Alive": "true", "ReplayedJournalId": "123",
                  "EditLogPort": "29010", "RpcPort": "29020", "HttpPort": "28030", "QueryPort": "29030",
                  "LastHeartbeat": "2026-09-24 15:00:00", "ErrMsg": "",
                  "CurrentConnected": "Yes" if index == 1 else "No"}
                 for index, node in enumerate(nodes[:3])]
    backends = [{"Host": node["ip"], "Alive": "true", "SystemDecommissioned": "false", "ErrMsg": "",
                 "HeartbeatPort": "29050", "BePort": "29060", "HttpPort": "28040", "BrpcPort": "28060",
                 "LastHeartbeat": "2026-09-24 15:00:00"}
                for node in nodes[3:]]
    return nodes, frontends, backends


def plan():
    workdir = cluster.ROOT / ".build-records" / "offline-multinode-shape-only"
    value = {"schema": 1, "tool": str(cluster.SOURCE), "workdir": str(workdir), "run_id": "a" * 32,
             "package": str(cluster.ROOT / "output" / "fixture"), "java_home": str(workdir / "jdk"),
             "host_namespace": "net:[1]", "LP009_complete": False, "release_performance_pass": False,
             "resource_profile": profile(), "planned_memory_with_reserve_mib": cluster.planned_memory_mib(profile()),
             "nodes": [], "bindings": {"tool": {"path": str(cluster.SOURCE)},
                 "sql_helper": {"path": str(cluster.SQL_SOURCE)}, "java": {"path": str(workdir / "jdk/bin/java")}}}
    for index, name in enumerate(cluster.NAMES):
        value["nodes"].append({"name": name, "component": name[:2], "ip": "10.254.23." + str(11 + index),
            "installation": str(workdir / name / name[:2]), "state_path": str(workdir / name / "node.json"),
            "ports": cluster.FE_PORTS if name.startswith("fe") else cluster.BE_PORTS, "bridge_peer": "lpv" + str(index),
            "resources": value["resource_profile"]["nodes"][name]})
    return value, workdir / "plan.json"


def node_record(value, node):
    namespace = "net:[2]"
    base = {"pid": 12345, "start_ticks": 500, "namespace": namespace, "exe": "/python", "cwd": str(cluster.ROOT),
            "command_sha256": "a" * 64}
    keeper = dict(base, kind="keeper", installation=str(Path(value["workdir"]) / "plan.json"), node_name=node["name"])
    service = dict(base, pid=12346, kind=node["component"], installation=node["installation"])
    return {"name": node["name"], "namespace": namespace, "keeper": keeper, "service": service,
            "launcher": None, "launcher_running": False}


class MultinodeBaselineTest(unittest.TestCase):
    def test_bootstrap_uses_local_metadata_before_any_backend_is_registered(self):
        nodes, frontends, _backends = membership()
        # Remote FE heartbeat fields are not yet ready during sequential bootstrap.
        frontends[1]["Alive"] = "false"
        frontends[1]["ReplayedJournalId"] = "0"
        sql = Mock()
        sql.execute.return_value = [{"update_count": 0}, {"rows": frontends}]
        keeper = {"pid": 12345}
        self.assertTrue(cluster.bootstrap_ready(sql, keeper, nodes[1]))
        sql.execute.assert_called_once_with(keeper, ["SET forward_to_master=false", "SHOW FRONTENDS"])

    def test_bootstrap_rejects_wrong_connection_role_join_and_ports(self):
        nodes, frontends, _backends = membership()
        for field, value in (("Host", nodes[0]["ip"]), ("Role", "OBSERVER"), ("Join", "false"),
                             ("CurrentConnected", "No"), ("QueryPort", "9030"), ("EditLogPort", "9010")):
            changed = copy.deepcopy(frontends)
            changed[1][field] = value
            sql = Mock()
            sql.execute.return_value = [{"update_count": 0}, {"rows": changed}]
            with self.subTest(field=field), self.assertRaises(ValueError):
                cluster.bootstrap_ready(sql, {}, nodes[1])

    def test_loaded_plan_cannot_redirect_paths_topology_or_resources(self):
        value, path = plan()
        self.assertIs(value, cluster.validate_plan(value, path))
        for field, changed in (("installation", str(cluster.ROOT / "output/other/fe")),
                               ("state_path", "/tmp/unowned.json"), ("ip", "127.0.0.1"),
                               ("name", "be1"), ("ports", {"query_port": 9030}),
                               ("resources", {"cpus": [0], "heap_mib": 1024})):
            modified = copy.deepcopy(value)
            modified["nodes"][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                cluster.validate_plan(modified, path)

    def test_node_record_cannot_borrow_a_different_plan_or_node_pin(self):
        value, _path = plan()
        node = value["nodes"][0]
        record = node_record(value, node)
        self.assertIs(record, cluster.validate_node_record(value, node, record))
        for which, field, changed in (("service", "installation", "/tmp/other/fe"),
                                      ("keeper", "node_name", "fe2"), ("keeper", "installation", "/tmp/plan.json"),
                                      ("service", "namespace", "net:[3]")):
            modified = copy.deepcopy(record)
            modified[which][field] = changed
            with self.subTest(which=which, field=field), self.assertRaises(ValueError):
                cluster.validate_node_record(value, node, modified)

    def test_rediscovery_cannot_replace_changed_known_identity(self):
        old = {"pid": 12345, "start_ticks": 500, "command_sha256": "old"}
        changed = dict(old, command_sha256="new")
        reused = dict(old, start_ticks=501)
        self.assertEqual([old], cluster.merge_pins([old], [changed, reused]))

    def test_bad_node_file_does_not_skip_known_service_or_other_nodes(self):
        value, _path = plan()
        first, second = value["nodes"][:2]
        records = {node["name"]: node_record(value, node) for node in (first, second)}
        records["fe2"]["keeper"]["pid"] = 22345
        records["fe2"]["service"]["pid"] = 22346
        records["fe2"]["namespace"] = "net:[3]"
        records["fe2"]["keeper"]["namespace"] = "net:[3]"
        records["fe2"]["service"]["namespace"] = "net:[3]"
        signalled = []
        def stopped(pins, grace=20):
            signalled.extend(pin["pid"] for pin in pins)
            return [{"identity": pin, "exited": True} for pin in pins]
        with patch.object(cluster.Path, "exists", return_value=True), \
                patch.object(cluster, "read", side_effect=ValueError("corrupt JSON")), \
                patch.object(cluster, "stop_pins", side_effect=stopped), \
                patch.object(cluster, "discover_services", return_value=[]), \
                patch.object(cluster, "live_namespace_processes", return_value=[]):
            result = cluster.cleanup_nodes(value, records)
        self.assertTrue({12345, 12346, 22345, 22346} <= set(signalled))
        self.assertFalse(result["complete"])
        self.assertTrue(result["errors"])

    def test_archive_failure_is_retained_without_throwing_before_cleanup(self):
        state = {"status": "STOPPED"}
        with patch.object(cluster, "save", side_effect=OSError("full filesystem")):
            cluster.cleanup_save(Path("/tmp/owned-evidence.json"), state)
        self.assertEqual("CLEANUP_FAILED", state["status"])
        self.assertTrue(state["archive_errors"])

    def test_explicit_profile_keeps_all_seven_nodes_and_conservative_budget(self):
        value = cluster.resources(profile(), {0, 1, 2, 3})
        self.assertEqual(3 * 1024 + 4 * (2048 + 256) + 4096, cluster.planned_memory_mib(value))
        for mutation in (lambda p: p["nodes"].pop("be4"), lambda p: p["nodes"]["fe1"].update(cpus=[9]),
                         lambda p: p["nodes"]["be1"].update(memory_mib=0),
                         lambda p: p.update(allow_existing_host_limits="true")):
            value = profile()
            mutation(value)
            with self.assertRaises(ValueError):
                cluster.resources(value, {0, 1, 2, 3})

    def test_original_jdk_options_are_preserved_but_heap_and_node_fields_are_explicit(self):
        source = 'JAVA_OPTS_FOR_JDK_17="-Xms8g -Xmx8192m -XX:+UseG1GC"\nhttp_port = 8030\n'
        result = cluster.configuration(source, {"http_port": 28030, "priority_networks": "10.254.23.11/32"}, 1024)
        self.assertIn('-Xms1024m -Xmx1024m -XX:+UseG1GC', result)
        self.assertEqual(1, result.count("http_port ="))
        self.assertIn("priority_networks = 10.254.23.11/32", result)
        with self.assertRaises(ValueError):
            cluster.configuration("JAVA_OPTS=broken", {}, 1024)

    def test_real_three_voters_four_backends_and_replay_watermark(self):
        nodes, frontends, backends = membership()
        self.assertTrue(cluster.check_membership(frontends, backends, nodes, 120, "10.254.23.12"))
        cases = [("Host", "10.254.23.11"), ("Role", "OBSERVER"), ("Join", "false"), ("Alive", "false"),
                 ("ClusterId", "other"), ("IsMaster", "true"), ("ReplayedJournalId", "119"),
                 ("RpcPort", "29021"), ("ErrMsg", "connection refused"), ("CurrentConnected", "No")]
        for field, value in cases:
            changed = copy.deepcopy(frontends)
            changed[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                cluster.check_membership(changed, backends, nodes, 120, "10.254.23.12")
        for field, value in (("Host", backends[0]["Host"]), ("Alive", "false"),
                             ("SystemDecommissioned", "true"), ("HeartbeatPort", "29051")):
            changed = copy.deepcopy(backends)
            changed[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                cluster.check_membership(frontends, changed, nodes, 120)

    def test_changed_process_identity_never_receives_a_signal(self):
        original = {"pid": 12345, "start_ticks": 500, "namespace": "net:[private]", "exe": "/java",
                    "cwd": "/owned", "command_sha256": "abc", "kind": "fe", "installation": "/owned"}
        for field, value in (("start_ticks", 501), ("namespace", "net:[host]"), ("exe", "/other"),
                             ("cwd", "/outside"), ("command_sha256", "different")):
            changed = dict(original, state="S")
            changed[field] = value
            with patch.object(cluster, "proc_data", return_value=changed), patch.object(cluster.os, "kill") as kill:
                result = cluster.stop_pins([original], grace=0)
                kill.assert_not_called()
                self.assertFalse(result[0]["exited"])
                self.assertIn("error", result[0])

    def test_already_exited_process_is_clean_without_signalling(self):
        with patch.object(cluster, "proc_data", side_effect=FileNotFoundError), patch.object(cluster.os, "kill") as kill:
            result = cluster.stop_pins([{"pid": 12345}], grace=0)
            kill.assert_not_called()
            self.assertTrue(result[0]["exited"])

    def test_package_external_symlink_and_directory_alias_are_not_silently_unfrozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            package.mkdir()
            (package / "file").write_text("original")
            self.assertEqual([package / "file"], cluster.package_files(package))
            (package / "escape").symlink_to(root)
            with self.assertRaises(ValueError):
                cluster.package_files(package)


if __name__ == "__main__":
    unittest.main()
