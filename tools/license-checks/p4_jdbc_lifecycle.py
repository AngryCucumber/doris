#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Optional single-window JDBC lifecycle; never infer A/B identity or launch services.

The caller supplies a fresh phase/identity/freeze context. The runner always waits
its own child before finish(), even when binding verification or handshake fails.
Only a bounded before-warmup handshake maps JVM timestamps; request and CPU
durations continue to use the original JVM differences.
"""

import json
import os
from pathlib import Path
import secrets
import time

import p4_jdbc_evidence as evidence
import p4_statistics as statistics


require = statistics.require
reference = statistics.reference
verify_reference = statistics.verify_reference
read_json = statistics.read_json


def anchor():
    before = time.monotonic_ns()
    utc = time.time_ns()
    return {"before_monotonic_ns": before, "utc_ns": utc, "after_monotonic_ns": time.monotonic_ns()}


def start_ticks(pid):
    value = Path("/proc", str(pid), "stat").read_text()
    return int(value[value.rfind(")") + 1:].split()[19])


def publish(path, value):
    """Atomic new receipt. Existing receipts are never replaced or reinterpreted."""
    path = Path(path)
    require(not path.exists(), "Lifecycle receipt already exists: " + path.name)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x") as stream:
        if isinstance(value, dict):
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write("\n")
        else:
            stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    # link avoids replace semantics: a concurrent existing destination is an error.
    os.link(temporary, path)
    temporary.unlink()


def properties(value):
    require(all("\n" not in str(item) and "\r" not in str(item) for item in value.values()),
            "Multiline handshake property")
    return "".join(key + "=" + str(item).replace("\\", "\\\\") + "\n" for key, item in value.items())


class LifecycleController:
    """One fresh owned JVM only. prepare -> attach -> poll -> waited finish.

    context_deadline_monotonic_ns bounds how long the caller's fresh context may
    wait before warmup is authorized, not the duration of the measured window.
    No identity field or execution phase is obtained from the legacy A/A report.
    """

    def __init__(self, workload, output, context, runner, helper, jar, classes):
        self.output = Path(output).resolve()
        self.process = None
        self.helper_ticks = None
        self.request = None
        self.bridge = None
        self.failure = None
        self.closed = False
        self.warmup_verified = False
        self.context = json.loads(json.dumps(context))
        now = time.monotonic_ns()
        deadline = context["context_deadline_monotonic_ns"]
        require(type(deadline) is int and now < deadline <= now + 300_000_000_000,
                "Expired or unbounded lifecycle context")
        require(context["phase"] in ("AA", "AB") and context["variant"] in ("A", "B"), "Invalid phase/variant")
        require(context["phase"] != "AA" or context["variant"] == "A", "A/A cannot launch B")
        require(isinstance(context["window_id"], str) and context["window_id"]
                and type(context["pair_id"]) is int and context["pair_id"] >= 0, "Missing window/pair identity")
        limit = context["max_clock_uncertainty_ns"]
        require(type(limit) is int and 0 < limit <= 1_000_000_000, "Invalid clock uncertainty limit")
        statistics.validate_identity(context["identity"])
        expected = {"runner", "calibrator", "jdbc_helper", "jdbc_driver", "fe_artifact", "be_artifact",
                    "environment", "configuration", "fixture", "client"}
        require(set(context["bindings"]) == expected, "Incomplete lifecycle execution bindings")
        self.dependencies = [context["workload"], *context["bindings"].values()]
        require(read_json(verify_reference(context["workload"])) == workload, "Workload differs from launch input")
        for key, source in (("runner", runner), ("jdbc_helper", helper), ("jdbc_driver", jar)):
            require(reference(source) == context["bindings"][key], "Actual launch input differs: " + key)
        for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"),
                           ("environment", "environment_sha256"), ("configuration", "configuration_sha256"),
                           ("fixture", "fixture_sha256"), ("client", "client_sha256")):
            require(context["bindings"][key]["sha256"] == context["identity"][field], "Identity differs: " + key)
        require(workload["build_identity"]["baseline_source_commit"] == context["identity"]["source_commit"],
                "Source commit differs from execution context")
        for key in ("fe_artifact", "be_artifact"):
            require(Path(workload["build_identity"][key]).resolve()
                    == Path(context["bindings"][key]["path"]).resolve(), "Workload binary differs: " + key)
        self.coordination = workload.get("coordination_timeout_seconds", 30)
        require(type(self.coordination) is int and 0 < self.coordination <= 300, "Unbounded coordination timeout")
        self.launch = {key: context[key] for key in ("window_id", "pair_id", "phase", "variant", "identity",
                       "bindings", "workload", "max_clock_uncertainty_ns", "context_deadline_monotonic_ns")}
        self.launch.update(schema_version=1, launch_token=secrets.token_hex(32), boot_id=statistics.boot_id(),
                           utc_anchor=anchor(), created_monotonic_ns=time.monotonic_ns(),
                           service_start_ticks={name: start_ticks(workload["services"][name]["pid"])
                                                for name in ("fe", "be")},
                           lifecycle_controller=reference(__file__),
                           compiled_helper_bindings=[reference(path) for path in sorted(Path(classes).rglob("*.class"))])
        require(self.launch["compiled_helper_bindings"], "Missing compiled helper")
        self.dependencies += [self.launch["lifecycle_controller"], *self.launch["compiled_helper_bindings"]]
        if context["phase"] == "AB":
            frozen = read_json(verify_reference(context["freeze"]))
            publication = read_json(verify_reference(context["publication"]))
            require(frozen["status"] == "FROZEN_ELIGIBLE"
                    and frozen["identities"][context["variant"]] == context["identity"], "Wrong frozen identity")
            require(publication["freeze"] == context["freeze"] and publication["boot_id"] == self.launch["boot_id"]
                    and publication["published_monotonic_ns"] <= self.launch["created_monotonic_ns"],
                    "Freeze must be published before launch")
            self.launch.update(freeze=context["freeze"], publication=context["publication"])
            self.dependencies += [context["freeze"], context["publication"]]
        else:
            require("freeze" not in context and "publication" not in context, "A/A cannot consume an A/B freeze")
        self.check_bindings()
        self.check_fresh()
        publish(self.output / "p4-launch.json", self.launch)
        self.launch_ref = reference(self.output / "p4-launch.json")
        self.dependencies.append(self.launch_ref)

    def settings(self):
        return {"p4_launch": self.launch_ref["path"], "p4_launch_sha256": self.launch_ref["sha256"],
                "p4_launch_token": self.launch["launch_token"], "p4_boot_id": self.launch["boot_id"]}

    def check_fresh(self):
        require(time.monotonic_ns() < self.launch["context_deadline_monotonic_ns"], "Lifecycle context expired before warmup")

    def check_bindings(self):
        for item in self.dependencies:
            verify_reference(item)

    def attach(self, process):
        require(self.process is None, "Lifecycle context cannot be reused")
        self.process = process
        self.helper_ticks = start_ticks(process.pid)
        self.check_fresh()

    def poll(self):
        if self.bridge is not None:
            if not self.warmup_verified and (self.output / "measurement-ready.json").exists():
                self.check_warmup()
                self.warmup_verified = True
            return
        require(self.process is not None and self.process.poll() is None, "Missing live owned helper")
        self.check_fresh()
        if self.request is None:
            ready_path = self.output / "p4-clock-ready.json"
            if not ready_path.exists():
                return
            ready = read_json(ready_path)
            self.check_receipt(ready)
            require(isinstance(ready["ready_nonce"], str) and len(ready["ready_nonce"]) >= 16,
                    "Missing helper readiness nonce")
            self.request = dict(self.settings(), nonce=secrets.token_hex(32), ready_nonce=ready["ready_nonce"])
            self.before = time.monotonic_ns()
            publish(self.output / "p4-clock-request.properties", properties(self.request))
            return
        require(time.monotonic_ns() - self.before <= self.coordination * 10**9, "Clock reply expired")
        reply_path = self.output / "p4-helper-clock.json"
        if not reply_path.exists():
            return
        reply = read_json(reply_path)
        after = time.monotonic_ns()
        self.check_receipt(reply)
        require(reply["nonce"] == self.request["nonce"], "Clock nonce does not match fresh request")
        bridge = {"schema_version": 1, "launch_token": self.launch["launch_token"],
                  "launch_sha256": self.launch_ref["sha256"], "boot_id": self.launch["boot_id"],
                  "nonce": reply["nonce"], "controller_before_ns": self.before, "controller_after_ns": after,
                  "helper_clock": reference(reply_path)}
        mapping = evidence.clock_bridge(self.launch, self.launch_ref, bridge, reply)
        self.check_bindings()
        self.check_fresh()
        require(start_ticks(self.process.pid) == self.helper_ticks, "Helper process lifetime changed")
        publish(self.output / "p4-clock-bridge.json", bridge)
        bridge_ref = reference(self.output / "p4-clock-bridge.json")
        ack = dict(self.request, helper_clock_sha256=bridge["helper_clock"]["sha256"], bridge_sha256=bridge_ref["sha256"])
        publish(self.output / "p4-clock-ack.properties", properties(ack))
        self.bridge = bridge_ref
        self.mapping = mapping
        self.dependencies += [bridge_ref, bridge["helper_clock"]]

    def check_receipt(self, receipt):
        require(receipt["schema_version"] == 1 and receipt["launch_token"] == self.launch["launch_token"]
                and receipt["launch_sha256"] == self.launch_ref["sha256"]
                and receipt["boot_id"] == self.launch["boot_id"], "Receipt belongs to another launch/boot")
        require(receipt["helper_pid"] == self.process.pid and receipt["helper_start_ticks"] == self.helper_ticks,
                "Receipt does not identify the owned helper")

    def check_warmup(self):
        ready = read_json(self.output / "measurement-ready.json")
        require(ready["launch_token"] == self.launch["launch_token"]
                and ready["launch_sha256"] == self.launch_ref["sha256"], "Warmup belongs to another launch")
        require(ready["warmup_start_ns"] + self.mapping["offset_upper_ns"]
                <= self.launch["context_deadline_monotonic_ns"], "Actual warmup began after context expiry")

    def finish(self, failure=None):
        """Must run after wait(), irrespective of earlier validation exceptions."""
        require(not self.closed, "Completion already recorded")
        require(self.process is not None and self.process.returncode is not None, "Helper must be waited before completion")
        self.closed = True
        errors = []
        if failure is not None:
            errors.append(type(failure).__name__)
        try:
            self.check_bindings()
        except (OSError, ValueError) as error:
            errors.append(type(error).__name__)
        remaining = []
        try:
            if start_ticks(self.process.pid) == self.helper_ticks:
                remaining.append(self.process.pid)
        except FileNotFoundError:
            pass
        if self.bridge is None:
            errors.append("MissingClockBridge")
        # Completion is a waited-controller boundary. If the conservative mapping
        # still extends beyond it, wait only that bounded uncertainty outside the
        # measurement interval; never alter original JVM CPU/latency timestamps.
        cleanup_path = self.output / "lifecycle.json"
        if self.bridge is not None:
            try:
                self.check_warmup()
                bound = read_json(cleanup_path)["cleanup_end_ns"] + self.mapping["offset_upper_ns"]
                delay = bound - time.monotonic_ns()
                if delay > 2 * self.launch["max_clock_uncertainty_ns"]:
                    errors.append("InvalidCleanupClockBound")
                elif delay > 0:
                    time.sleep(delay / 1e9)
            except (OSError, ValueError, KeyError, TypeError):
                errors.append("InvalidWarmupOrCleanupEvidence")
        completed = {"schema_version": 1, "launch_token": self.launch["launch_token"],
                     "launch_sha256": self.launch_ref["sha256"], "boot_id": statistics.boot_id(),
                     "helper_pid": self.process.pid, "helper_start_ticks": self.helper_ticks,
                     "exit_code": self.process.returncode, "completed_monotonic_ns": time.monotonic_ns(),
                     "utc_anchor": anchor(), "remaining_live_pids": remaining, "bridge": self.bridge,
                     "controller_errors": errors}
        publish(self.output / "p4-completion.json", completed)
        require(not errors and not remaining and self.process.returncode == 0, "JDBC lifecycle did not complete cleanly")
        return reference(self.output / "p4-completion.json")
