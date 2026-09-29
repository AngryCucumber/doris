#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Freeze current P4 A-only evidence and compare audited independent A/B windows.

This is a statistics/binding layer, not a protocol runner or a raw-result oracle.
Each normalized window must be bound to its protocol auditor and raw artifacts.
Neither an old fixture PASS nor a synthetic metric proves a real window executed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import time


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = (ROOT / "docs/license-certificate-execution-plan-20260922.md",
             ROOT / "docs/license-p0-contract-20260922.md")
MINIMUMS = {"G1": (120, 300), "G2": (180, 600), "G3": (180, 600),
            "G4": (180, 600), "G5": (0, 600), "G6": (0, 600), "G7": (0, 300)}
# Positive differences always mean harm; these ceilings cannot expand with noise.
METRICS = {"success_qps": (-1, 1.0), "p95_ms": (1, 2.0), "p99_ms": (1, 2.0),
           "fe_cpu_seconds_per_success": (1, 1.0), "be_cpu_seconds_per_success": (1, 1.0)}
IDENTITY_FIELDS = ("source_commit", "fe_sha256", "be_sha256", "environment_sha256",
                   "configuration_sha256", "fixture_sha256", "client_sha256")


class EvidenceError(ValueError):
    """Evidence is missing, inconsistent, stale, or outside the frozen scope."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def read_json(path):
    def invalid(value):
        raise EvidenceError("Non-finite JSON value: " + value)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), parse_constant=invalid, object_pairs_hook=unique)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def reference(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": digest(path)}


def verify_reference(item):
    require(isinstance(item, dict) and set(item) == {"path", "sha256"}, "Invalid artifact reference")
    require(Path(item["path"]).is_absolute(), "Artifact paths must be absolute")
    require(digest(item["path"]) == item["sha256"], "Artifact digest changed: " + item["path"])
    return Path(item["path"]).resolve()


def file_identity(path):
    info = Path(path).stat()
    return info.st_dev, info.st_ino


def numeric(value, name, minimum=0, strictly_positive=False):
    require(type(value) in (int, float) and math.isfinite(value)
            and (value > minimum if strictly_positive else value >= minimum), "Invalid " + name)
    return value


def quantile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    index = int(position)
    return ordered[index] + (ordered[min(index + 1, len(ordered) - 1)] - ordered[index]) * (position - index)


def bootstrap(paired, seed, draws=10000):
    """Resample independent pairs, never requests or slices of one long window."""
    require(len(paired) >= 5 and draws >= 10000, "Need five independent pairs and 10000 bootstrap draws")
    require(all(type(value) in (int, float) and math.isfinite(value) for value in paired),
            "Non-finite paired difference")
    rng = random.Random(seed)
    means = [statistics.fmean(rng.choices(paired, k=len(paired))) for _ in range(draws)]
    low, high = quantile(means, .025), quantile(means, .975)
    return {"mean_percent": statistics.fmean(paired), "ci95_percent": [low, high],
            "confidence_radius_percent": (high - low) / 2,
            "paired_harm_percent": paired, "pair_count": len(paired), "resamples": draws}


def metric_analysis(pairs, seed, phase):
    result = {}
    for metric, (direction, limit) in METRICS.items():
        differences = []
        for first, second in pairs:
            a, b = first["metrics"][metric], second["metrics"][metric]
            require(a > 0 and b > 0, "Zero metric cannot establish relative precision: " + metric)
            differences.append(direction * 200 * (b - a) / (a + b))
        metric_seed = int.from_bytes(hashlib.sha256((str(seed) + ":" + metric).encode()).digest()[:8], "big")
        analysis = bootstrap(differences, metric_seed)
        low, high = analysis["ci95_percent"]
        noise = quantile([abs(value) for value in differences], .95)
        precision = analysis["confidence_radius_percent"] <= limit
        if phase == "AA":
            # A/A has no intentional treatment; either directional drift invalidates its noise model.
            status = ("AA_DIRECTIONAL_DRIFT" if low > 0 or high < 0 else
                      "AA_PRECISION_INSUFFICIENT" if not precision else "AA_ELIGIBLE")
        else:
            # Measurable harmful drift is failure even when smaller than the resolution ceiling.
            status = ("REGRESSION" if low > 0 else
                      "INCONCLUSIVE" if not precision or high > limit else "PASS")
        analysis.update(status=status, resolution_band_percent=limit, precision_target_percent=limit,
                        absolute_pair_p95_percent=noise, adverse_direction="decrease" if direction < 0 else "increase")
        result[metric] = analysis
    return result


def validate_identity(identity):
    require(isinstance(identity, dict) and set(identity) == set(IDENTITY_FIELDS), "Incomplete build/environment identity")
    for field, value in identity.items():
        size = 40 if field == "source_commit" else 64
        require(isinstance(value, str) and len(value) == size and all(c in "0123456789abcdef" for c in value),
                "Invalid identity digest: " + field)


def validate_cell(cell):
    require(cell["group"] in MINIMUMS and isinstance(cell["id"], str) and cell["id"].startswith(cell["group"] + "-"),
            "Cell must name one current G1-G7 subcase")
    warmup, duration = MINIMUMS[cell["group"]]
    require(type(cell["warmup_seconds"]) is int and cell["warmup_seconds"] >= warmup, "Warmup below current G minimum")
    require(type(cell["duration_seconds"]) is int and cell["duration_seconds"] >= duration, "Duration below current G minimum")
    require(type(cell["concurrency"]) is int and cell["concurrency"] > 0, "Invalid concurrency")
    require(isinstance(cell["connection_mode"], str) and cell["connection_mode"], "Missing connection mode")
    require(cell["rate_fraction"] in (.30, .60, .85), "Rate fraction must be 30%, 60%, or 85%")
    require(cell["rate_fraction"] == .60 if cell["group"] in ("G5", "G6", "G7") else
            cell["rate_fraction"] in (.30, .85), "Rate fraction differs from current group")
    numeric(cell["rate"], "offered rate", strictly_positive=True)
    require(isinstance(cell["workload_sha256"], str) and len(cell["workload_sha256"]) == 64,
            "Missing exact workload digest")
    require(cell["seed"] == 20260922 and isinstance(cell["arrival_schedule_sha256"], str)
            and len(cell["arrival_schedule_sha256"]) == 64, "Missing fixed open-loop schedule binding")
    require(type(cell["request_count"]) is int and cell["request_count"] >= 10000,
            "Frozen window needs at least 10000 scheduled business operations")
    numeric(cell["slo"]["p99_ms"], "P99 SLO", strictly_positive=True)
    numeric(cell["slo"]["max_drain_seconds"], "drain SLO")
    require(cell["slo"]["max_error_rate"] == 0 and cell["slo"]["max_timeout_rate"] == 0,
            "Formal successful business windows require zero unexpected errors/timeouts")


def capacity_evidence(item, cell, baseline_identity):
    """Independently re-derive the bracket from controller audits; retain their bindings.

    Protocol correctness is proved by those audits, not by capacity flags alone.
    This checks the current controller report schema and does not re-run services.
    """
    report_path = verify_reference(item)
    report = read_json(report_path)
    frozen, bracket, trials = report["frozen_inputs"], report["bracket"], report["trials"]
    require(frozen.get("phase") == "A_ONLY" and frozen["mode"] == "confirm", "Capacity must be an A-only confirmation")
    require(frozen["current_group"] == cell.get("baseline_group", cell["group"])
            and frozen["cell_id"] == cell.get("baseline_cell_id", cell["id"]), "Wrong capacity cell")
    require(frozen.get("business_workload_sha256") == cell["workload_sha256"], "Capacity used a different business workload")
    require(frozen.get("baseline_identity") == baseline_identity, "Capacity used a different A environment/configuration/client")
    require(frozen["p99_slo_ms"] == cell["slo"]["p99_ms"]
            and frozen["max_drain_seconds"] == cell["slo"]["max_drain_seconds"], "SLO changed after calibration")
    template = frozen["template"]
    require(template["pairs"] >= 5 and template["warmup_seconds"] >= MINIMUMS[cell["group"]][0]
            and template["duration_seconds"] >= MINIMUMS[cell["group"]][1], "Capacity confirmation is too short")
    require(template["concurrency"] == cell["concurrency"]
            and template.get("connection_mode", "reuse") == cell["connection_mode"], "Capacity load shape changed")
    bindings = [item]
    for name, binding in frozen["bindings"].items():
        verify_reference(binding)
        bindings.append(binding)
        if name in ("fe_artifact", "be_artifact"):
            require(binding["sha256"] == baseline_identity[name.replace("_artifact", "_sha256")], "Wrong capacity binary")
    require({"fe_artifact", "be_artifact"}.issubset(frozen["bindings"]), "Missing capacity binary bindings")
    require([trial["rate"] for trial in trials] == frozen["rates"] and len(trials) >= 2,
            "Calibration omitted a predeclared rate")
    outcomes = []
    for trial in trials:
        require(trial["exit_code"] == 0 and not trial.get("watchdog_terminated")
                and not trial.get("frozen_input_errors"), "Invalid capacity trial lifecycle")
        audit_ref = reference(trial["artifact_audit"])
        audit = read_json(audit_ref["path"])
        bindings.append(audit_ref)
        require(audit.get("valid") is True and not audit.get("errors"), "Unverified capacity raw artifacts")
        require(audit.get("raw_artifact_bindings"), "Capacity audit lacks actual raw artifact bindings")
        for binding in audit["raw_artifact_bindings"]:
            verify_reference(binding)
            bindings.append(binding)
        windows = audit["windows"]
        require(len(windows) == 2 * template["pairs"], "Missing capacity windows")
        for window in windows:
            count = window["successful_requests"]
            require(type(count) is int and count >= 10000 and window["scheduled_requests"] == count
                    and window["observed_requests"] == count and window["missing_requests"] == 0
                    and not window["errors"] and window["cpu_boundary_verified"] is True,
                    "Capacity evidence has failures or insufficient samples")
            numeric(window["p99_ms"], "capacity P99")
            numeric(window["drain_seconds"], "capacity drain")
        outcome = "within_slo" if all(window["p99_ms"] <= cell["slo"]["p99_ms"]
                and window["drain_seconds"] <= cell["slo"]["max_drain_seconds"] for window in windows) else "outside_slo"
        require(trial["assessment"] == outcome, "Capacity assessment disagrees with audited windows")
        outcomes.append((trial["rate"], outcome))
    passes = [rate for rate, outcome in outcomes if outcome == "within_slo"]
    failures = [rate for rate, outcome in outcomes if outcome == "outside_slo"]
    require(passes and failures and max(passes) < min(failures), "No monotonic confirmed capacity bracket")
    lower, upper = max(passes), min(failures)
    require((upper - lower) / lower <= .01 + 1e-12, "Capacity bracket wider than 1%")
    require(bracket.get("capacity_bracket_established") is True
            and bracket["largest_tested_rate_within_slo"] == lower
            and bracket["smallest_tested_rate_outside_slo_above_it"] == upper, "Capacity summary mismatch")
    # Decimal rates are allowed. No integer truncation can silently turn a nonzero rate into zero.
    require(math.isclose(cell["rate"], lower * cell["rate_fraction"], rel_tol=1e-12), "Offered rate differs from frozen capacity fraction")
    return {"confirmed_lower_rate": lower, "confirmed_upper_rate": upper, "bindings": bindings}


def validate_windows(windows, cell, identities, expected_order, before_ns=None, after_ns=None):
    require(len(windows) == 2 * len(expected_order) and len(expected_order) >= 5, "Missing independent pairs")
    ids, audits, raw_paths, spans = set(), set(), set(), []
    pairs = []
    for pair_index, order in enumerate(expected_order):
        pair = windows[2 * pair_index:2 * pair_index + 2]
        require("".join(window["variant"] for window in pair) == order, "Executed pair order differs from freeze")
        for window in pair:
            require(window["pair_id"] == pair_index and window["window_id"] not in ids, "Duplicate or wrongly paired window")
            ids.add(window["window_id"])
            require(window["boot_id"] == boot_id(), "Window uses another monotonic clock domain")
            require(window["identity"] == identities[window["variant"]], "Window identity differs from freeze")
            require(window["workload_sha256"] == cell["workload_sha256"] and window["rate"] == cell["rate"], "Window load changed")
            require(window["arrival_schedule_sha256"] == cell["arrival_schedule_sha256"], "Arrival schedule changed")
            require(window["warmup_seconds"] == cell["warmup_seconds"]
                    and window["duration_seconds"] == cell["duration_seconds"], "Window duration changed")
            start, end = window["start_monotonic_ns"], window["end_monotonic_ns"]
            warm_start, warm_end = window["warmup_start_monotonic_ns"], window["warmup_end_monotonic_ns"]
            domain = window.get("monotonic_clock_domain")
            if domain == "controller_monotonic_exact":
                uncertainty = window.get("monotonic_mapping_uncertainty_ns", 0)
                require(uncertainty == 0, "Exact monotonic domain cannot carry a nonzero mapping uncertainty")
            else:
                require(domain == "bounded_jvm_mapping", "Window lacks a proven exact or bounded clock domain")
                mapping = window["monotonic_mapping"]
                uncertainty = window["monotonic_mapping_uncertainty_ns"]
                low, mid, high = (mapping[key] for key in ("offset_lower_ns", "estimated_offset_ns", "offset_upper_ns"))
                require(all(type(value) is int for value in (low, mid, high, uncertainty)) and low <= mid <= high
                        and uncertainty == max(mid - low, high - mid), "Invalid bounded monotonic mapping")
            require(type(start) is int and type(end) is int and 0 <= start < end, "Invalid monotonic boundary")
            require(type(warm_start) is int and type(warm_end) is int and 0 <= warm_start <= warm_end <= start
                    and warm_end - warm_start >= cell["warmup_seconds"] * 10**9, "Invalid actual warmup interval")
            require((before_ns is None or end + uncertainty <= before_ns)
                    and (after_ns is None or warm_start - uncertainty >= after_ns),
                    "Window not measured in the frozen A-only/A-B phase")
            require(end - start >= cell["duration_seconds"] * 10**9, "One long run cannot be relabelled as full windows")
            spans.append((warm_start - uncertainty, end + uncertainty))
            count = window["successful_requests"]
            require(type(count) is int and count == cell["request_count"] and window["scheduled_requests"] == count
                    and window["observed_requests"] == count, "Missing, failed, or fewer than 10000 successful business operations")
            require(window["error_count"] == 0 and window["timeout_count"] == 0
                    and window["retry_count"] == 0, "Unexpected errors, timeouts, or retries cannot be hidden in success throughput")
            require(all(window[key] is True for key in ("oracle_verified", "cleanup_verified", "cpu_boundary_verified")),
                    "Window lacks actual correctness, cleanup, or CPU boundary evidence")
            seconds = numeric(window["effective_duration_seconds"], "effective duration", strictly_positive=True)
            require(math.isclose(seconds, (end - start) / 1e9, rel_tol=1e-12, abs_tol=1e-9),
                    "Effective duration differs from the actual request interval")
            require(seconds >= cell["duration_seconds"] and seconds - cell["duration_seconds"] <= cell["slo"]["max_drain_seconds"],
                    "Backlog violates frozen SLO")
            metrics = window["metrics"]
            require(set(metrics) == set(METRICS), "Incomplete primary metrics")
            for metric, value in metrics.items():
                numeric(value, metric, strictly_positive=True)
            require(math.isclose(metrics["success_qps"], count / seconds, rel_tol=1e-9), "Throughput does not include drain")
            require(metrics["p95_ms"] <= metrics["p99_ms"] <= cell["slo"]["p99_ms"], "Latency violates frozen ordering/SLO")
            evidence_path = verify_reference(window["evidence"])
            require(str(evidence_path) not in audits, "Duplicate evidence cannot prove independent windows")
            audits.add(str(evidence_path))
            evidence = read_json(evidence_path)
            require(evidence.get("status") == "VERIFIED" and evidence["window"] == {key: value for key, value in window.items() if key != "evidence"},
                    "Normalized window differs from its protocol audit")
            verify_reference(evidence["auditor"])
            for item in evidence.get("dependency_bindings", []):
                verify_reference(item)
            require(evidence["raw_artifacts"], "No raw request artifacts")
            for item in evidence["raw_artifacts"]:
                raw_path = file_identity(verify_reference(item))
                require(raw_path not in raw_paths, "Raw request receipts were reused across independent windows")
                raw_paths.add(raw_path)
        pairs.append(tuple(pair if order != "BA" else reversed(pair)))
    require(all(first[1] <= second[0] for first, second in zip(spans, spans[1:])),
            "Measurement windows overlap or are out of execution order")
    return pairs


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def freeze(inputs):
    created_ns = time.monotonic_ns()
    require(inputs["schema_version"] == 1, "Unsupported input schema")
    cell = inputs["cell"]
    validate_cell(cell)
    for identity in inputs["identities"].values():
        validate_identity(identity)
    require(set(inputs["identities"]) == {"A", "B"}, "Need exact A and B identity")
    first, second = inputs["identities"]["A"], inputs["identities"]["B"]
    require(first["fe_sha256"] != second["fe_sha256"], "A and B cannot use the same FE artifact")
    for field in IDENTITY_FIELDS:
        if field not in ("fe_sha256", "source_commit"):
            require(first[field] == second[field], "A/B must share " + field)
    capacity = capacity_evidence(inputs["capacity_report"], cell, first)
    order = inputs["ab_order"]
    require(isinstance(order, list) and len(order) >= 5 and set(order) == {"AB", "BA"}
            and abs(order.count("AB") - order.count("BA")) <= 1, "Predeclare a balanced A/B order with at least five pairs")
    aa_windows = inputs["aa_windows"]
    require(len(aa_windows) % 2 == 0, "Incomplete A/A pair")
    pairs = validate_windows(aa_windows, cell, inputs["identities"], ["AA"] * (len(aa_windows) // 2), before_ns=created_ns)
    analysis = metric_analysis(pairs, 20260922, "AA")
    eligible = all(item["status"] == "AA_ELIGIBLE" for item in analysis.values())
    return {"schema_version": 1, "status": "FROZEN_ELIGIBLE" if eligible else "FROZEN_INCONCLUSIVE",
            "created_utc": datetime.now(timezone.utc).isoformat(), "created_monotonic_ns": time.monotonic_ns(),
            "boot_id": boot_id(), "phase": "A_ONLY", "cell": cell, "identities": inputs["identities"],
            "capacity": capacity, "aa_windows": aa_windows, "aa_analysis": analysis, "ab_order": order,
            "contracts": [reference(path) for path in CONTRACTS], "analyzer": reference(__file__),
            "method": {"seed": 20260922, "resamples": 10000, "confidence": .95,
                       "interval": "percentile bootstrap of independent paired-window mean symmetric relative harm",
                       "pair_harm": "direction * 200 * (B-A)/(A+B)",
                       "resolution_percent": {metric: limit for metric, (_, limit) in METRICS.items()},
                       "repeated_regression": "A positive lower CI bound is harmful directional drift; retain every independent repeat as a new analysis, never replace a failed run",
                       "no_peeking": "All A/A, capacity, SLO, order, and method are fixed before any formal B window"},
            "scope": "Business metrics only. Page/import/rejection costs and state propagation are separate observations."}


def compare(frozen, inputs):
    require(frozen["schema_version"] == inputs["schema_version"] == 1, "Unsupported comparison schema")
    require(frozen["phase"] == "A_ONLY" and frozen["boot_id"] == boot_id(), "Freeze is not from this monotonic clock domain")
    publication = read_json(verify_reference(inputs["publication"]))
    verify_reference(publication["freeze"])
    require(publication["freeze"]["sha256"] == inputs["actual_freeze_sha256"]
            and publication["boot_id"] == frozen["boot_id"]
            and publication["published_monotonic_ns"] >= frozen["created_monotonic_ns"],
            "Freeze publication receipt does not match")
    for item in frozen["contracts"] + [frozen["analyzer"]] + frozen["capacity"]["bindings"]:
        verify_reference(item)
    require(frozen["contracts"] == [reference(path) for path in CONTRACTS], "Current G contract changed after freeze")
    # Re-evaluate A/A instead of trusting a writable status/analysis flag in a hand-edited file.
    aa_pairs = validate_windows(frozen["aa_windows"], frozen["cell"], frozen["identities"],
                                ["AA"] * (len(frozen["aa_windows"]) // 2), before_ns=frozen["created_monotonic_ns"])
    aa_analysis = metric_analysis(aa_pairs, 20260922, "AA")
    require(aa_analysis == frozen["aa_analysis"], "A/A analysis changed after freeze")
    require(frozen["method"]["resolution_percent"] == {metric: limit for metric, (_, limit) in METRICS.items()},
            "Resolution bands were widened")
    require(frozen["method"]["seed"] == 20260922 and frozen["method"]["resamples"] == 10000
            and frozen["method"]["confidence"] == .95, "Statistical method changed")
    require(isinstance(frozen["ab_order"], list) and len(frozen["ab_order"]) >= 5
            and set(frozen["ab_order"]) == {"AB", "BA"}
            and abs(frozen["ab_order"].count("AB") - frozen["ab_order"].count("BA")) <= 1,
            "Frozen pair order is unbalanced")
    if frozen["status"] != "FROZEN_ELIGIBLE" or any(item["status"] != "AA_ELIGIBLE" for item in aa_analysis.values()):
        return {"status": "INCONCLUSIVE", "reason": "A/A noise, precision, or directional drift is not qualified", "analysis": {}}
    require(inputs["freeze_sha256"] == inputs["actual_freeze_sha256"], "Comparison does not bind the executed freeze")
    windows = inputs["windows"]
    for window in windows:
        require(window["freeze_sha256"] == inputs["actual_freeze_sha256"]
                and window["freeze_publication_sha256"] == inputs["publication"]["sha256"],
                "Window did not bind this freeze before execution")
    pairs = validate_windows(windows, frozen["cell"], frozen["identities"], frozen["ab_order"],
                             before_ns=time.monotonic_ns(), after_ns=publication["published_monotonic_ns"])
    old_ids = {window["window_id"] for window in frozen["aa_windows"]}
    require(not old_ids.intersection(window["window_id"] for window in windows), "An A/A window was reused as an A/B observation")
    def raw_paths(items):
        return {file_identity(binding["path"]) for window in items
                for binding in read_json(window["evidence"]["path"])["raw_artifacts"]}
    require(not raw_paths(frozen["aa_windows"]).intersection(raw_paths(windows)), "A/A raw requests were reused in A/B")
    analysis = metric_analysis(pairs, 20260922, "AB")
    statuses = {item["status"] for item in analysis.values()}
    status = "FAIL" if "REGRESSION" in statuses else "INCONCLUSIVE" if "INCONCLUSIVE" in statuses else "PASS"
    return {"status": status, "cell_id": frozen["cell"]["id"], "analysis": analysis,
            "window_count": len(windows), "freeze_sha256": inputs["freeze_sha256"],
            "scope": "One frozen business comparison; does not imply all G1-G7 or page P99 passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "compare"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--freeze", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "Never overwrite a frozen input or previous result")
    seal_path = args.output.with_suffix(args.output.suffix + ".published.json")
    require(args.mode != "freeze" or not seal_path.exists(), "Never overwrite a freeze publication receipt")
    try:
        inputs = read_json(args.input)
        if args.mode == "freeze":
            require(args.freeze is None, "freeze does not accept --freeze")
            result = freeze(inputs)
        else:
            require(args.freeze is not None, "compare needs --freeze")
            inputs["actual_freeze_sha256"] = digest(args.freeze)
            inputs["publication"] = reference(args.freeze.with_suffix(args.freeze.suffix + ".published.json"))
            result = compare(read_json(args.freeze), inputs)
        result["input"] = reference(args.input)
    except (EvidenceError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        result = {"status": "INCONCLUSIVE", "reason": str(error), "error_type": type(error).__name__}
    with args.output.open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    if args.mode == "freeze" and result["status"] in ("FROZEN_ELIGIBLE", "FROZEN_INCONCLUSIVE"):
        publication = {"freeze": reference(args.output), "published_monotonic_ns": time.monotonic_ns(),
                       "boot_id": boot_id()}
        with seal_path.open("x") as stream:
            json.dump(publication, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"status": result["status"], "output": str(args.output.resolve())}))
    return 0 if result["status"] in ("PASS", "FROZEN_ELIGIBLE") else 2


if __name__ == "__main__":
    raise SystemExit(main())
