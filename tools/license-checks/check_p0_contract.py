#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Validate the FE-only P0 contract against independently discovered source entries.

This is a static design gate, not a proof of runtime authorization or performance.
It never updates the approved inventory automatically. Source drift must be reviewed.
"""

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

JAVA = "fe/fe-core/src/main/java/org/apache/doris/"
DEFAULT_CONTRACT = "docs/license-p0-contract-20260922.json"
MAPPING = re.compile(r"^\s*@(Request|Get|Post|Put|Delete|Patch)Mapping\b", re.M)
FUNCTION = re.compile(r"\b(?:scalar|agg|aggregate|window|tableGenerating|tableValued)\(\s*(\w+)\.class\s*,(.*?)\)", re.S)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_comments(text):
    # Preserve literals and line positions; comments are not executable registrations.
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m[0])
                  if m[0].startswith(("//", "/*")) else m[0], text)


def discover(root):
    result = {}
    result["sql_command_candidate_files"] = sorted(
        str(p.relative_to(root)) for p in (root / JAVA / "nereids/trees/plans/commands").rglob("*Command.java"))
    result["table_function_candidate_files"] = sorted(
        str(p.relative_to(root)) for p in (root / JAVA / "tablefunction").glob("*TableValuedFunction.java")
        if p.name != "TableValuedFunctionIf.java")
    http = []
    # Scan all FE Java modules, not only the packages previously in the inventory.
    for path in (root / "fe").rglob("*.java"):
        if "/src/main/java/" not in str(path):
            continue
        source = strip_comments(path.read_text(encoding="utf-8"))
        for match in MAPPING.finditer(source):
            line = source.count("\n", 0, match.end()) + 1
            http.append([str(path.relative_to(root)), line])
    result["fe_http_mapping_annotation_sites"] = sorted(http)
    thrift = root / "gensrc/thrift/FrontendService.thrift"
    if thrift.exists():
        source = strip_comments(thrift.read_text(encoding="utf-8"))
        body = source.split("service FrontendService", 1)[1]
        result["FrontendService_method_declarations"] = sorted(
            re.findall(r"^\s*[\w.<> ,]+\s+(\w+)\s*\(", body, re.M))
    else:
        result["FrontendService_method_declarations"] = []
    for family in ("Scalar", "Aggregate", "Window", "TableGenerating", "TableValued"):
        path = root / JAVA / ("catalog/Builtin" + family + "Functions.java")
        values = []
        if path.exists():
            for match in FUNCTION.finditer(strip_comments(path.read_text(encoding="utf-8"))):
                values.append([match[1], re.findall(r'"([^"\\]*)"', match[2])])
        result["builtin_" + family] = sorted(values)
    return result


def expected_inventory(coverage):
    result = {}
    for entry in coverage["entries"]:
        group = entry["group"]
        if group in ("sql_command_candidate_files", "table_function_candidate_files"):
            value = entry["path"]
        elif group == "fe_http_mapping_annotation_sites":
            value = [entry["path"], entry["line"]]
        elif group == "FrontendService_method_declarations":
            value = entry["entry"]
        elif group.startswith("builtin_"):
            value = [entry["entry"], entry["names"]]
        else:
            continue
        result.setdefault(group, []).append(value)
    return {key: sorted(value) for key, value in result.items()}


def resolve_performance_prerequisites(contract, performance):
    """Resolve setup from its sole source; never accept a second prose copy.

    The whole-manifest hash proves which input was reviewed. It cannot detect an
    outdated setup copied into an otherwise valid phase mapping, so validate the
    reference and the remaining display fields independently of that hash.
    """
    errors, resolved = [], {}
    cases = {case["id"]: case for case in performance["cases"]}
    phases = contract["performance_phase_mapping"]
    if len(cases) != len(performance["cases"]):
        errors.append("Duplicate performance case IDs")
    if set(cases) != set(phases):
        errors.append("Performance phase mapping differs from case IDs")
    for case_id, phase in phases.items():
        case = cases.get(case_id)
        if case is None:
            continue
        if "prerequisites" in phase:
            errors.append(case_id + " has a copied prerequisites field; use prerequisites_ref only")
        expected_ref = {"manifest": contract["performance_manifest"], "case_id": case_id, "field": "setup"}
        if phase.get("prerequisites_ref") != expected_ref:
            errors.append(case_id + " has an invalid prerequisites_ref")
            continue
        for field in ("name", "environment"):
            if phase.get(field) != case.get(field):
                errors.append(case_id + " phase " + field + " differs from the performance case")
        setup = case.get("setup")
        if not isinstance(setup, list) or not setup or any(
                not isinstance(value, str) or not value.strip() for value in setup):
            errors.append(case_id + " referenced setup must contain non-empty instructions")
            continue
        resolved[case_id] = setup
    return errors, resolved


def validate_runtime_test_specs(contract):
    """Check usable test definitions without claiming their behavior was run.

    This checks explicit inputs/oracles and source/fixture references, not the
    semantic completeness or runtime reachability of SQL and protocol templates.
    """
    errors = []
    fixture_contract = contract.get("runtime_test_fixture_contract", {})
    fixtures = fixture_contract.get("fixtures", {})
    if fixture_contract.get("status") != "specified_not_executed" or not fixtures:
        errors.append("Runtime test fixture contract is missing or claims execution")
    valid_transports = {"sql", "http", "http_sql", "sql_protocol", "thrift", "flight", "fe_test", "browser"}
    all_inputs = set()
    for item in contract["coverage_requirements"]:
        for test in item["tests"]:
            test_id = test["id"]
            scenario = "".join(test["scenario"].split())

            def is_concrete(value):
                return (isinstance(value, str) and bool(value.strip())
                        and "".join(value.split()) != scenario
                        and value.strip().lower() not in {"todo", "tbd", "待定", "待补", "same as scenario"})

            def require_text_list(value, label):
                if not isinstance(value, list) or not value or any(not is_concrete(x) for x in value):
                    errors.append(test_id + " lacks concrete " + label)

            refs = test.get("fixture_refs", [])
            if (not isinstance(refs, list) or not refs or any(not isinstance(x, str) for x in refs)
                    or any(x not in fixtures for x in refs)):
                errors.append(test_id + " has missing/unknown fixture refs")
            for field in ("preconditions", "side_effect_oracles", "cleanup_oracles"):
                require_text_list(test.get(field), field)
            expected = test.get("expected_outcome", {})
            require_text_list(expected.get("assertions") if isinstance(expected, dict) else None,
                              "expected outcome assertions")
            steps = test.get("steps")
            if not isinstance(steps, list) or not steps:
                errors.append(test_id + " has no operation steps")
            else:
                for step in steps:
                    if not isinstance(step, dict):
                        errors.append(test_id + " has invalid operation step")
                        continue
                    if step.get("transport") not in valid_transports:
                        errors.append(test_id + " has unknown test transport")
                    for field in ("entry", "principal", "input"):
                        if not is_concrete(step.get(field)):
                            errors.append(test_id + " lacks concrete step " + field)
                signature = json.dumps(steps, ensure_ascii=False, sort_keys=True)
                if signature in all_inputs:
                    errors.append(test_id + " duplicates another test's entire operation sequence")
                all_inputs.add(signature)
            evidence = test.get("input_evidence", {})
            if not isinstance(evidence, dict):
                errors.append(test_id + " lacks input evidence metadata")
                continue
            if evidence.get("status") != "specified_not_executed":
                errors.append(test_id + " static input evidence must not claim runtime execution")
            require_text_list(evidence.get("source_refs"), "source references")
            require_text_list(evidence.get("unverified_dependencies"), "unverified dependency boundaries")
    return errors


def validate(root, contract):
    errors = []
    coverage = json.loads((root / contract["coverage_manifest"]).read_text())
    performance = json.loads((root / contract["performance_manifest"]).read_text())
    entries = coverage["entries"]
    check = lambda condition, message: errors.append(message) if not condition else None
    check(len({e["id"] for e in entries}) == len(entries), "Duplicate coverage entry IDs")
    counts = dict(Counter(e["current_release_disposition"] for e in entries))
    check(counts == contract["scope_counts"], "FE scope counts differ from approved contract")
    check(counts == coverage["counts"]["by_current_release_disposition"], "Coverage counts are inconsistent")
    c_items = {c["id"]: c for c in coverage["coverage_item_dispositions"]}
    frozen_c = {c["id"]: c for c in contract["coverage_requirements"]}
    check(set(c_items) == {"C%02d" % n for n in range(1, 49)} == set(frozen_c), "C01-C48 coverage incomplete")
    hook_ids = {h["id"] for h in contract["hooks"]}
    tests = set()
    for cid, item in frozen_c.items():
        check(item["scope"] == c_items.get(cid, {}).get("current_release_disposition"), cid + " scope differs")
        check(set(item["hooks"]) <= hook_ids, cid + " refers to unknown hook")
        if item["scope"] == "out_of_scope_user_accepted":
            check(not item["tests"], cid + " must not claim runtime guard tests")
        else:
            check(bool(item["hooks"]) and len(item["tests"]) >= 2, cid + " lacks hook or positive/negative tests")
            expected_ids = {"P0-" + cid + "-POSITIVE", "P0-" + cid + "-NEGATIVE"}
            check({test["id"] for test in item["tests"]} == expected_ids,
                  cid + " changed the stable positive/negative test IDs")
            check({test["kind"] for test in item["tests"]} == {"positive", "negative"},
                  cid + " lacks distinct positive/negative test kinds")
        for test in item["tests"]:
            check(test["id"] not in tests, "Duplicate test ID " + test["id"])
            tests.add(test["id"])
            check(test["status"] == "specified_not_executed", "Static contract cannot mark a runtime test passed")
            for source in test.get("input_evidence", {}).get("source_refs", []):
                check(isinstance(source, str) and (root / source).is_file(),
                      test["id"] + " refers to a missing source file")
    errors.extend(validate_runtime_test_specs(contract))
    reqs = {r["id"] for r in coverage["requirements"]}
    check(reqs == {"R%02d" % n for n in range(1, 21)} == set(contract["requirement_mapping"]), "R01-R20 mapping incomplete")
    for rid, cids in contract["requirement_mapping"].items():
        check(bool(cids) and set(cids) <= set(c_items), rid + " has invalid C mapping")
    entry_mapping = contract["entry_mapping"]
    check(set(entry_mapping) == {e["id"] for e in entries}, "P0 entry mapping must cover every inventory ID")
    for entry in entries:
        check(bool(entry.get("current_hook")), entry["id"] + " lacks current FE boundary")
        check(set(entry["current_plan_refs"]) <= set(c_items), entry["id"] + " has invalid current C refs")
        mapping = entry_mapping.get(entry["id"], {})
        refs = mapping.get("coverage_refs", [])
        check(set(refs) <= set(c_items), entry["id"] + " has invalid frozen C mapping")
        check(mapping.get("scope") == entry["current_release_disposition"], entry["id"] + " changed scope")
        check(set(entry["current_plan_refs"]) <= set(refs), entry["id"] + " drops a current C requirement")
        if entry["current_release_disposition"] != "out_of_scope_user_accepted":
            check(bool(refs), entry["id"] + " has no active frozen C requirement")
    discovered = discover(root)
    expected = expected_inventory(coverage)
    for group, values in discovered.items():
        check(values == expected.get(group, []), "Registration drift: " + group)
    hashes_checked = 0
    for name, expected_hash in coverage["source_sha256"].items():
        path = root / name
        check(path.is_file() and digest(path) == expected_hash, "Historical source drift: " + name)
        hashes_checked += 1
    for hook in contract["hooks"]:
        for anchor in hook["source_anchors"]:
            path = root / anchor["path"]
            if not path.is_file():
                errors.append("Missing hook source: " + anchor["path"])
                continue
            source = path.read_text(encoding="utf-8")
            check(anchor["text"] in source, hook["id"] + " anchor missing: " + anchor["text"])
            check(digest(path) == anchor["source_sha256"], hook["id"] + " source changed: " + anchor["path"])
    for watch in contract["watched_source_directories"]:
        current = sorted(str(p.relative_to(root)) for p in (root / watch["path"]).rglob("*.java"))
        check(current == watch["files"], "New/removed source requires review: " + watch["path"])
    lp_ids = {c["id"] for c in performance["cases"]}
    check(lp_ids == {"LP-%03d" % n for n in range(1, 27)}
          == set(contract["performance_phase_mapping"]), "LP-001-LP-026 phase mapping incomplete")
    prerequisite_errors, prerequisites = resolve_performance_prerequisites(contract, performance)
    errors.extend(prerequisite_errors)
    check(contract["performance_policy_sha256"] == digest(root / contract["performance_manifest"]),
          "Performance input contract changed; review measurement inputs before rerunning")
    source_errors = (root / JAVA / "common/ErrorCode.java").read_text()
    occupied = {int(n) for n in re.findall(r"\bERR_\w+\s*\(\s*(\d+)", source_errors)}
    for number in contract["api"]["reserved_mysql_error_numbers"]:
        check(number not in occupied, "Reserved license errno conflicts with existing code: " + str(number))
    operations = (root / JAVA / "persist/OperationType.java").read_text()
    used_operations = {int(n) for n in re.findall(r"\bOP_\w+\s*=\s*(\d+)", operations)}
    for number in contract["persistence"]["reserved_fe_journal_opcodes"]:
        check(number not in used_operations, "Reserved license journal opcode conflicts: " + str(number))
    return {"schema_version": 1, "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "passed" if not errors else "failed", "evidence_scope": "static_P0_design_contract_only",
            "runtime_enforcement_proven": False, "performance_pass_proven": False,
            "coverage_entries": len(entries), "scope_counts": counts, "source_hashes_checked": hashes_checked,
            "registration_counts": {k: len(v) for k, v in discovered.items()},
            "hooks": len(hook_ids), "specified_future_runtime_tests": len(tests),
            "requirements": len(reqs), "performance_cases": len(lp_ids),
            "resolved_performance_prerequisite_cases": len(prerequisites), "errors": errors}


def self_test():
    """Mutation checks prove the discovery gate observes new source registrations."""
    samples = [
        (JAVA + "nereids/trees/plans/commands/NewCommand.java", "class NewCommand {}", "sql_command_candidate_files"),
        (JAVA + "tablefunction/NewTableValuedFunction.java", "class NewTableValuedFunction {}", "table_function_candidate_files"),
        ("fe/new-module/src/main/java/test/NewController.java", '@GetMapping("/new")\nvoid read() {}', "fe_http_mapping_annotation_sites"),
        ("gensrc/thrift/FrontendService.thrift", "service FrontendService {\n string newRead(1: string p)\n}", "FrontendService_method_declarations"),
        (JAVA + "catalog/BuiltinScalarFunctions.java", 'scalar(NewRead.class, "new_read", "new_alias")', "builtin_Scalar"),
    ]
    results = []
    for name, source, group in samples:
        with tempfile.TemporaryDirectory(prefix="license-p0-mutation-") as temp:
            root = Path(temp)
            before = discover(root)
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            after = discover(root)
            if before[group] == after[group] or len(after[group]) != 1:
                raise AssertionError("Mutation was not discovered: " + group)
            results.append({"mutation": group, "status": "passed"})
    return results


def performance_reference_self_test():
    """Exercise drift that a matching whole-file digest alone cannot detect."""
    source = {"cases": [{"id": "LP-001", "name": "Point query", "environment": "isolated",
                         "setup": ["Confirm SHORT-CIRCUIT in EXPLAIN; no ordinary profile is produced"]}]}
    contract = {"performance_manifest": "performance.json", "performance_phase_mapping": {
        "LP-001": {"name": "Point query", "environment": "isolated", "prerequisites_ref": {
            "manifest": "performance.json", "case_id": "LP-001", "field": "setup"}}}}
    results = []
    errors, resolved = resolve_performance_prerequisites(contract, source)
    if errors or resolved["LP-001"] != source["cases"][0]["setup"]:
        raise AssertionError("Valid performance reference did not resolve its actual setup")
    results.append({"mutation": "valid_setup_reference", "status": "passed"})

    mutations = [
        ("copied_stale_setup", lambda phase: phase.update(prerequisites=["Require ordinary point-query profile"])),
        ("wrong_case_reference", lambda phase: phase["prerequisites_ref"].update(case_id="LP-002")),
        ("wrong_manifest_reference", lambda phase: phase["prerequisites_ref"].update(manifest="old.json")),
        ("wrong_field_reference", lambda phase: phase["prerequisites_ref"].update(field="action")),
        ("stale_environment", lambda phase: phase.update(environment="previous_environment")),
        ("stale_display_name", lambda phase: phase.update(name="Previous case")),
    ]
    for name, mutate in mutations:
        changed = deepcopy(contract)
        # The source file and its reviewed digest stay unchanged for these cases.
        mutate(changed["performance_phase_mapping"]["LP-001"])
        if not resolve_performance_prerequisites(changed, source)[0]:
            raise AssertionError("Performance contract drift was not rejected: " + name)
        results.append({"mutation": name, "status": "passed"})

    for name, setup in (("missing_setup", None), ("empty_setup", []), ("invalid_setup_type", [1])):
        changed_source = deepcopy(source)
        changed_source["cases"][0]["setup"] = setup
        if not resolve_performance_prerequisites(contract, changed_source)[0]:
            raise AssertionError("Invalid referenced setup was accepted: " + name)
        results.append({"mutation": name, "status": "passed"})

    changed_source = deepcopy(source)
    changed_source["cases"][0]["setup"].append("Verify row-store, MoW and light-schema table properties")
    errors, resolved = resolve_performance_prerequisites(contract, changed_source)
    if errors or resolved["LP-001"] != changed_source["cases"][0]["setup"]:
        raise AssertionError("A reviewed source setup change was not inherited by the reference")
    results.append({"mutation": "source_setup_change_is_resolved", "status": "passed"})
    changed_source["cases"].append(deepcopy(changed_source["cases"][0]))
    if not resolve_performance_prerequisites(contract, changed_source)[0]:
        raise AssertionError("Ambiguous duplicate performance case ID was accepted")
    results.append({"mutation": "duplicate_source_case_id", "status": "passed"})
    return results


def runtime_spec_self_test(contract):
    """Reject hollow scenario copies and unproven passes in future test inputs."""
    if validate_runtime_test_specs(contract):
        raise AssertionError("The real runtime test specification is invalid before mutation")
    mutations = [
        ("empty_preconditions", lambda test: test.update(preconditions=["  "])),
        ("scenario_only_preconditions", lambda test: test.update(preconditions=[test["scenario"]])),
        ("unknown_fixture", lambda test: test.update(fixture_refs=["F-DOES-NOT-EXIST"])),
        ("missing_input", lambda test: test["steps"][0].pop("input")),
        ("scenario_only_input", lambda test: test["steps"][0].update(input=test["scenario"])),
        ("missing_principal", lambda test: test["steps"][0].update(principal="")),
        ("missing_expected_result", lambda test: test.update(expected_outcome={"assertions": []})),
        ("missing_side_effect_oracle", lambda test: test.update(side_effect_oracles=[])),
        ("missing_cleanup_oracle", lambda test: test.update(cleanup_oracles=[])),
        ("unproven_runtime_pass", lambda test: test["input_evidence"].update(status="passed")),
        ("missing_source_ref", lambda test: test["input_evidence"].update(source_refs=[])),
        ("missing_unverified_boundary", lambda test: test["input_evidence"].update(unverified_dependencies=[])),
    ]
    results = []
    for name, mutate in mutations:
        changed = deepcopy(contract)
        test = next(item["tests"][0] for item in changed["coverage_requirements"] if item["tests"])
        mutate(test)
        if not validate_runtime_test_specs(changed):
            raise AssertionError("Invalid runtime test specification was accepted: " + name)
        results.append({"mutation": name, "status": "passed"})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    contract = json.loads((args.root / args.contract).read_text(encoding="utf-8"))
    report = validate(args.root, contract)
    if args.self_test:
        report["mutation_tests"] = self_test()
        report["performance_reference_tests"] = performance_reference_self_test()
        report["runtime_spec_tests"] = runtime_spec_self_test(contract)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
