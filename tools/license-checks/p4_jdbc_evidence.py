#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Read JDBC raw receipts into P4 windows; never launch clients or infer missing time.

The existing JDBC verifier supplies CSV/vector/oracle/driver/CPU checks. A real
controller and helper must supply the launch, clock handshake, warmup and waited
completion receipts described in jdbc-lifecycle-required-fields.json. Old A-only
smokes can be inspected, but missing lifecycle receipts cannot be retrofitted.
"""

import argparse
import json
from pathlib import Path

import calibrate_read_capacity as capacity
import p4_statistics as statistics
import run_performance_baseline as baseline


require = statistics.require
read_json = statistics.read_json
reference = statistics.reference
verify_reference = statistics.verify_reference
EvidenceError = statistics.EvidenceError


def utc_anchor(value):
    require(set(value) == {"before_monotonic_ns", "utc_ns", "after_monotonic_ns"}, "Missing bounded UTC anchor")
    require(all(type(item) is int and item >= 0 for item in value.values()), "Invalid UTC anchor")
    require(value["before_monotonic_ns"] <= value["after_monotonic_ns"], "Reversed UTC anchor interval")
    return value


def clock_bridge(launch, launch_ref, bridge, helper):
    """A reply sample occurred somewhere inside the controller's request interval.

    The midpoint is an estimate, not an assertion of equal JVM/Python clock epochs.
    Relative JDBC timings continue to use the original same-JVM differences.
    """
    for record in (bridge, helper):
        require(record["schema_version"] == 1 and record["launch_token"] == launch["launch_token"]
                and record["launch_sha256"] == launch_ref["sha256"] and record["boot_id"] == launch["boot_id"],
                "Clock receipt belongs to another launch or boot")
    require(bridge["nonce"] == helper["nonce"] and isinstance(helper["nonce"], str) and len(helper["nonce"]) >= 16,
            "Clock handshake nonce does not match")
    before, after, sample = bridge["controller_before_ns"], bridge["controller_after_ns"], helper["jvm_sample_ns"]
    require(all(type(value) is int and value >= 0 for value in (before, after, sample)), "Invalid clock sample")
    require(launch["created_monotonic_ns"] <= before <= after, "Clock handshake predates launch or is reversed")
    limit = launch["max_clock_uncertainty_ns"]
    require(type(limit) is int and 0 < limit <= 1_000_000_000, "Invalid predeclared clock uncertainty limit")
    low, high = before - sample, after - sample
    midpoint = (low + high) // 2
    uncertainty = max(midpoint - low, high - midpoint)
    require(uncertainty <= limit, "Clock mapping exceeds predeclared uncertainty")
    return {"offset_lower_ns": low, "offset_upper_ns": high, "estimated_offset_ns": midpoint,
            "uncertainty_ns": uncertainty, "scope": "Bounded same-boot interprocess clock mapping; no exact global epoch claim"}


def launch_bindings(launch):
    require(launch["schema_version"] == 1 and launch["phase"] in ("AA", "AB")
            and launch["variant"] in ("A", "B"), "Invalid actual execution phase/variant")
    require(launch["phase"] != "AA" or launch["variant"] == "A", "A/A launch cannot contain candidate B")
    require(isinstance(launch["launch_token"], str) and len(launch["launch_token"]) >= 16, "Missing unique launch token")
    require(type(launch["created_monotonic_ns"]) is int and launch["created_monotonic_ns"] >= 0, "Missing launch clock")
    require(isinstance(launch["boot_id"], str) and launch["boot_id"], "Missing actual boot identity")
    utc_anchor(launch["utc_anchor"])
    statistics.validate_identity(launch["identity"])
    required = {"runner", "calibrator", "jdbc_helper", "jdbc_driver", "fe_artifact", "be_artifact",
                "environment", "configuration", "fixture", "client"}
    bindings = launch["bindings"]
    require(set(bindings) == required, "Incomplete execution tool/configuration bindings")
    for binding in bindings.values():
        verify_reference(binding)
    for key, path in (("runner", baseline.__file__), ("calibrator", capacity.__file__), ("jdbc_helper", baseline.SOURCE)):
        require(bindings[key]["sha256"] == statistics.digest(path), "Executed JDBC source differs from the selected verifier: " + key)
    for key, field in (("fe_artifact", "fe_sha256"), ("be_artifact", "be_sha256"),
                       ("environment", "environment_sha256"), ("configuration", "configuration_sha256"),
                       ("fixture", "fixture_sha256"), ("client", "client_sha256")):
        require(bindings[key]["sha256"] == launch["identity"][field], "Execution identity does not bind " + key)
    workload = read_json(verify_reference(launch["workload"]))
    require(workload.get("contract_group") in ("G1", "G2"), "This adapter only handles the current JDBC G1/G2 workloads")
    baseline.contract_inputs(workload)
    require(workload["build_identity"]["baseline_source_commit"] == launch["identity"]["source_commit"],
            "Executed source commit differs from launch identity")
    for key in ("fe_artifact", "be_artifact"):
        require(Path(workload["build_identity"][key]).resolve() == Path(bindings[key]["path"]).resolve(),
                "Workload points at another binary")
    binding = baseline.business_workload_binding(workload)
    require(workload.get("business_workload_sha256") == binding["sha256"], "Business workload was not frozen canonically")
    return workload, binding


def inspect_trial(manifest):
    """Re-read an existing actual calibration trial, including every raw request."""
    directory = Path(manifest["trial_directory"]).resolve()
    frozen = read_json(verify_reference(manifest["frozen_inputs"]))
    input_path = verify_reference(manifest["input_workload"])
    workload = read_json(input_path)
    report = read_json(directory / "report.json")
    errors = capacity.check_bindings(frozen["bindings"])
    require(not errors, "Executed calibration bindings changed: " + ", ".join(errors))
    audit = capacity.verify_trial(directory, report, workload, frozen, input_path)
    require(audit["valid"] is True, "Raw trial verification failed: " + ", ".join(audit["errors"]))
    lifecycle = [name for name in ("p4-launch.json", "p4-clock-bridge.json", "p4-helper-clock.json", "p4-completion.json")
                 if any(not (directory / ("window-%02d" % index) / name).is_file()
                        for index in range(len(audit["windows"])))]
    missing_warmup = any("warmup_start_ns" not in read_json(directory / ("window-%02d" % index) / "measurement-ready.json")
                         for index in range(len(audit["windows"])))
    return {"status": "JDBC_RAW_TRIAL_VERIFIED_NOT_PERFORMANCE", "audit": audit,
            "inputs": manifest, "missing_normalization_receipts": lifecycle,
            "missing_actual_warmup_interval": missing_warmup,
            "formal_performance_pass": False,
            "scope": "Offline recomputation of actual JDBC receipts; no inferred lifecycle or upgraded historical claim"}


def normalize(manifest):
    directory = Path(manifest["window_directory"]).resolve()
    require(directory.is_dir(), "Missing actual JDBC window directory")
    raw_before = capacity.raw_artifact_bindings(directory)
    launch_path = verify_reference(manifest["launch"])
    completion_path = verify_reference(manifest["completion"])
    launch, completion = read_json(launch_path), read_json(completion_path)
    workload, business = launch_bindings(launch)
    for key in ("launch_token", "boot_id"):
        require(completion[key] == launch[key], "Completion belongs to another launch")
    require(completion["schema_version"] == 1 and completion["launch_sha256"] == manifest["launch"]["sha256"],
            "Completion does not bind the executed launch")
    require(completion["exit_code"] == 0 and completion["remaining_live_pids"] == [], "JDBC helper did not finish cleanly")
    require(not completion.get("controller_errors", []), "Controller rejected JDBC lifecycle evidence")
    utc_anchor(completion["utc_anchor"])
    bridge_path = verify_reference(completion["bridge"])
    bridge = read_json(bridge_path)
    helper_path = verify_reference(bridge["helper_clock"])
    helper = read_json(helper_path)
    require(type(helper["helper_pid"]) is int and helper["helper_pid"] > 0
            and type(helper["helper_start_ticks"]) is int and helper["helper_start_ticks"] > 0,
            "Missing actual helper lifetime")
    require(all(helper[key] == completion[key] for key in ("helper_pid", "helper_start_ticks")),
            "Waited process differs from the helper clock process")
    mapping = clock_bridge(launch, manifest["launch"], bridge, helper)
    ready = read_json(directory / "measurement-ready.json")
    require(ready["launch_token"] == launch["launch_token"] and ready["launch_sha256"] == manifest["launch"]["sha256"],
            "Warmup receipt does not bind the actual launch")
    start = read_json(directory / "measurement-start.json")
    end = read_json(directory / "measurement-end.json")
    cleanup = read_json(directory / "lifecycle.json")
    warm_start, warm_end = ready["warmup_start_ns"], ready["warmup_end_ns"]
    require(all(type(value) is int and value >= 0 for value in (warm_start, warm_end, ready["ready_ns"])),
            "Missing actual helper warmup timestamps")
    require(helper["jvm_sample_ns"] <= warm_start <= warm_end <= ready["ready_ns"] <= start["epoch_ns"],
            "Clock/warmup/request ordering is invalid")
    require(warm_end - warm_start >= workload["warmup_seconds"] * 10**9, "Actual warmup was shorter than declared")
    offset, uncertainty = mapping["estimated_offset_ns"], mapping["uncertainty_ns"]
    require(warm_start + mapping["offset_lower_ns"] >= launch["created_monotonic_ns"],
            "Conservative clock bounds cannot prove launch before warmup")
    if "context_deadline_monotonic_ns" in launch:
        require(warm_start + mapping["offset_upper_ns"] <= launch["context_deadline_monotonic_ns"],
                "Actual warmup exceeds the bounded launch context lifetime")
    require(type(completion["completed_monotonic_ns"]) is int
            and cleanup["cleanup_end_ns"] + mapping["offset_upper_ns"] <= completion["completed_monotonic_ns"],
            "Conservative clock bounds cannot prove cleanup before waited completion")
    summary = read_json(directory / "summary.json")
    derived = capacity.verify_window(directory, summary, workload, launch["service_start_ticks"])
    require(summary.get("harness_retries") == 0
            and not any(value is not None for value in summary.get("warmup_failure", [])),
            "Unexpected retry or failed warmup")
    window = {"window_id": launch["window_id"], "pair_id": launch["pair_id"], "variant": launch["variant"],
              "boot_id": launch["boot_id"], "identity": launch["identity"], "workload_sha256": business["sha256"],
              "arrival_schedule_sha256": derived["arrival_sha256"], "rate": workload["rate"],
              "warmup_seconds": workload["warmup_seconds"], "duration_seconds": workload["duration_seconds"],
              "warmup_start_monotonic_ns": warm_start + offset, "warmup_end_monotonic_ns": warm_end + offset,
              "start_monotonic_ns": start["epoch_ns"] + offset,
              "end_monotonic_ns": end["request_interval_end_ns"] + offset,
              "monotonic_mapping_uncertainty_ns": uncertainty,
              "monotonic_clock_domain": "bounded_jvm_mapping", "monotonic_mapping": mapping,
              "effective_duration_seconds": (end["request_interval_end_ns"] - start["epoch_ns"]) / 1e9,
              "scheduled_requests": derived["scheduled_requests"], "observed_requests": derived["observed_requests"],
              "successful_requests": derived["successful_requests"], "error_count": 0, "timeout_count": 0,
              "retry_count": 0, "oracle_verified": True, "cleanup_verified": True, "cpu_boundary_verified": True,
              "metrics": {key: derived[key] for key in statistics.METRICS}}
    if launch["phase"] == "AB":
        frozen = read_json(verify_reference(launch["freeze"]))
        publication = read_json(verify_reference(launch["publication"]))
        require(frozen["status"] == "FROZEN_ELIGIBLE" and frozen["identities"][launch["variant"]] == launch["identity"],
                "A/B execution does not match an eligible frozen identity")
        require(publication["freeze"] == launch["freeze"] and publication["boot_id"] == launch["boot_id"],
                "A/B publication does not bind this freeze/boot")
        require(publication["published_monotonic_ns"] <= launch["created_monotonic_ns"]
                and publication["published_monotonic_ns"] <= window["warmup_start_monotonic_ns"] - uncertainty,
                "Freeze was not published before this launch and warmup")
        window.update(freeze_sha256=launch["freeze"]["sha256"], freeze_publication_sha256=launch["publication"]["sha256"])
    else:
        require("freeze" not in launch and "publication" not in launch, "A-only launch cannot pretend to be a frozen A/B execution")
    raw_after = capacity.raw_artifact_bindings(directory)
    require(raw_before == raw_after, "JDBC raw receipts changed during normalization")
    raw = {str(Path(item["path"]).resolve()): item for item in raw_after}
    for item in (manifest["launch"], manifest["completion"], completion["bridge"], bridge["helper_clock"]):
        path = verify_reference(item)
        raw[str(path)] = item
    dependencies = [launch["workload"], *launch["bindings"].values()]
    if "lifecycle_controller" in launch:
        dependencies.extend([launch["lifecycle_controller"], *launch["compiled_helper_bindings"]])
    if launch["phase"] == "AB":
        dependencies.extend([launch["freeze"], launch["publication"]])
    for item in dependencies:
        verify_reference(item)
    minimum_warmup, minimum_duration = statistics.MINIMUMS[workload["contract_group"]]
    return {"status": "VERIFIED", "window": window, "auditor": reference(__file__),
            "raw_artifacts": list(raw.values()), "dependency_bindings": dependencies,
            "clock_mapping": mapping, "utc_anchors": [launch["utc_anchor"], completion["utc_anchor"]],
            "formal_shape_met": workload["warmup_seconds"] >= minimum_warmup
                and workload["duration_seconds"] >= minimum_duration and derived["successful_requests"] >= 10000,
            "scope": "One real JDBC window normalized from receipts; not A/A precision, capacity, or A/B acceptance",
            "retry_scope": summary["retry_scope"]}


def verify_sequence(audits):
    """Conservative cross-JVM order proof, without changing same-JVM durations."""
    require(audits, "Missing normalized windows")
    previous_upper = None
    boot = None
    for audit in audits:
        require(audit["status"] == "VERIFIED", "Unverified window in sequence")
        window = audit["window"]
        if boot is None:
            boot = window["boot_id"]
        require(window["boot_id"] == boot, "Window sequence crosses boot/clock domains")
        uncertainty = window["monotonic_mapping_uncertainty_ns"]
        lower = window["warmup_start_monotonic_ns"] - uncertainty
        upper = window["end_monotonic_ns"] + uncertainty
        require(previous_upper is None or previous_upper <= lower,
                "Conservative clock intervals cannot prove independent nonoverlapping windows")
        previous_upper = upper
    return {"verified": True, "windows": len(audits), "scope": "Warmup/request intervals separated under recorded clock uncertainty"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect-trial", "normalize"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "Never overwrite an audit or normalization failure")
    manifest = read_json(args.input)
    if args.mode == "normalize":
        directory = Path(manifest["window_directory"]).resolve()
        require(directory not in args.output.resolve().parents, "Normalization output must not mutate the raw window")
    try:
        result = normalize(manifest) if args.mode == "normalize" else inspect_trial(manifest)
    except (EvidenceError, KeyError, TypeError, ValueError, OSError) as error:
        result = {"status": "REJECTED", "error_type": type(error).__name__, "reason": str(error),
                  "formal_performance_pass": False}
    with args.output.open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    response = {"status": result["status"], "audit": reference(args.output)}
    if result["status"] == "VERIFIED":
        response["window"] = dict(result["window"], evidence=response["audit"])
    print(json.dumps(response, ensure_ascii=False))
    return 2 if result["status"] == "REJECTED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
