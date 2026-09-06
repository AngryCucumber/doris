#!/usr/bin/env python3
# MassDB SQL implementation.
# Licensing decision pending (A02); see dist/source-headers.json.
# This file does not assert an ASF contributor agreement.
"""Validate explicitly registered non-ASF headers and upstream modification notices."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PENDING = (
    "MassDB SQL implementation.\n"
    "Licensing decision pending (A02); see dist/source-headers.json.\n"
    "This file does not assert an ASF contributor agreement.\n"
)


def pending_header(path):
    if path.suffix == ".less":
        return "/*\n" + "".join(" * " + line + "\n" for line in PENDING.splitlines()) + " */\n"
    prefix = "# " if path.suffix == ".py" or path.name.startswith("Dockerfile") else "// "
    return "".join(prefix + line + "\n" for line in PENDING.splitlines())


def apache_pattern(root=ROOT):
    company = json.loads((root / "dist/product-provenance.json").read_text())
    copyright_block = (r"// Copyright \(c\) [0-9]{4}(?:-[0-9]{4})?\r?\n// "
                       + re.escape(company["companyZh"]) + r"\r?\n// "
                       + re.escape(company["companyEn"]) + r"\r?\n")
    spdx = r"// SPDX-License-Identifier: Apache-2\.0\r?\n"
    body = (root / "dist/headers/apache-2.0.txt").read_text().splitlines()
    generic = r"\r?\n".join(re.escape("// " + line if line else "//") for line in body) + r"\r?\n"
    return r"\A(?:" + copyright_block + spdx + "|(?:" + copyright_block + "(?:" + spdx + ")?)?" + generic + ")"


def check(root=ROOT, release=False):
    policy = json.loads((root / "dist/source-headers.json").read_text())
    attributes = root / ".gitattributes"
    archive_exclusions = re.findall(r"^([^*\s]+/)\s+export-ignore\s*$", attributes.read_text(), re.M) \
        if attributes.is_file() and not (root / ".git").exists() else []
    registered = policy["pending"] + policy["apache"]
    if len(registered) != len(set(registered)):
        raise ValueError("Duplicate source-header registration")
    for name in registered:
        path = root / name
        text = path.read_text(encoding="utf-8")
        if text.startswith("#!"):
            text = text.split("\n", 1)[1]
        if name in policy["pending"]:
            if not text.startswith(pending_header(path)):
                raise ValueError(f"Missing or changed pending-license header: {name}")
        else:
            # Existing Compose files and the independent test retain their prior Apache grant.
            if path.suffix == ".yml":
                text = "\n".join("//" + line[1:] if line.startswith("#") else line
                                 for line in text.split("\n"))
            if not re.match(apache_pattern(root), text):
                raise ValueError(f"Invalid independently authored Apache header: {name}")
            if "Licensed to the Apache Software Foundation" in text.split("\n\n", 1)[0]:
                raise ValueError(f"Unexpected ASF contributor statement: {name}")
    upstream_count = 0
    for name, record in policy["modifiedUpstream"].items():
        if not (root / name).exists() and any(name.startswith(prefix) for prefix in archive_exclusions):
            continue  # git archive intentionally omits these files; checkout CI still requires them.
        text = (root / name).read_text(encoding="utf-8")
        start = text.find("Licensed to the Apache Software Foundation")
        end = text.find("under the License.", start) + len("under the License.")
        if start < 0 or hashlib.sha256(text[start:end].encode()).hexdigest() != record["originalHeaderSha256"]:
            raise ValueError(f"Original upstream header removed or changed: {name}")
        if record["notice"] not in text[:end + 300]:
            raise ValueError(f"Missing modification/source notice: {name}")
        upstream_count += 1
    for path in (root / "fe").glob("**/src/*/java/**/massdb/**/*.java"):
        if path.relative_to(root).as_posix() not in policy["apache"]:
            raise ValueError(f"Register independent Java source and its license: {path}")
    config = (root / ".licenserc.yaml").read_text()
    block = config.split("# BEGIN MassDB separately checked headers\n", 1)[1].split(
        "# END MassDB separately checked headers", 1)[0]
    expected = sorted(registered + ["fe/**/src/*/java/**/massdb/**/*.java"])
    if sorted(re.findall(r'- "([^"]+)"', block)) != expected:
        raise ValueError("License Eyes exceptions differ from the separately checked registry")
    checks = ET.parse(root / "fe/check/checkstyle/checkstyle.xml")
    independent = next(module for module in checks.getroot().findall("module")
                       if any(p.get("name") == "id" and p.get("value") == "independentHeader"
                              for p in module.findall("property")))
    if independent.find("property[@name='format']").get("value") != apache_pattern(root):
        raise ValueError("Checkstyle independent-header pattern differs from the reviewed templates")
    if release and policy["pending"]:
        raise ValueError(f"Release blocked: licensing decision A02 is pending for {len(policy['pending'])} files. "
                         "Review headers pass only for development; select and apply the actual license first.")
    return len(policy["pending"]), len(policy["apache"]), upstream_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="Reject any unresolved license status")
    args = parser.parse_args()
    try:
        pending, apache, upstream = check(release=args.release)
        print(f"Source headers verified: {pending} pending, {apache} independent Apache, {upstream} upstream")
    except (ValueError, OSError, KeyError, IndexError, ET.ParseError) as exc:
        sys.exit(f"Source headers: {exc}")
