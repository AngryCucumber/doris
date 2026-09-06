#!/usr/bin/env python3
# MassDB SQL implementation.
# Licensing decision pending (A02); see dist/source-headers.json.
# This file does not assert an ASF contributor agreement.
"""Prepare and verify product notices without placing source archives in the UI."""

import sys

if sys.version_info < (3, 9):
    sys.exit("Product notices require Python 3.9+. Set MASSDB_NOTICE_PYTHON to a supported interpreter.")

import argparse
import collections
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_text(path):
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"Empty notice: {path}")
    return text


def source_identity():
    """Use checkout/archive evidence when available; unknown provenance can build locally."""
    commit = None
    modified = None
    if (ROOT / ".git").exists():
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            dirty = subprocess.check_output([
                "git", "status", "--porcelain", "--untracked-files=normal", "--",
                ".", ":!.claude", ":!.claude/**",
            ], cwd=ROOT, text=True)
            modified = bool(dirty.strip())
        except (OSError, subprocess.CalledProcessError):
            commit = None
    archive_path = ROOT / "dist/source-version.json"
    if not commit and archive_path.is_file():
        archive = json.loads(read_text(archive_path))
        if re.fullmatch(r"[0-9a-f]{40}", archive.get("sourceCommit", "")):
            commit, modified = archive["sourceCommit"], archive.get("sourceModified")
    override = os.environ.get("MASSDB_SOURCE_COMMIT")
    if override:
        if not re.fullmatch(r"[0-9a-f]{40}", override):
            raise ValueError("MASSDB_SOURCE_COMMIT must contain the full 40-character commit hash")
        if commit and commit != override:
            raise ValueError("MASSDB_SOURCE_COMMIT conflicts with checkout/archive provenance")
        commit = override
    return {"sourceCommit": commit or "unknown", "sourceModified": modified}


def check_release_provenance():
    data = source_identity()
    if not re.fullmatch(r"[0-9a-f]{40}", data["sourceCommit"]):
        raise ValueError("Release requires source provenance: build from a clean checkout or git archive")
    if data["sourceModified"] is not False:
        raise ValueError("Release requires a clean source checkout or verified git archive; "
                         "commit the intended changes first. MASSDB_SOURCE_COMMIT alone does not verify source contents.")


def inventory_java_package(package, destination):
    """Inventory actual JARs, nested JARs and embedded notices; do not infer legal approval."""
    package = package.resolve()
    destination = destination.resolve()
    if not package.is_dir() or destination.is_relative_to(package):
        raise ValueError("Use an existing package and a separate inventory destination")
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "notices").mkdir()
    archives = {}
    occurrences = []
    cache = Path.home() / ".m2/repository"

    def nested_occurrences(item, location, component, depth):
        if depth > 8:
            raise ValueError(f"Excessive nested JAR depth: {location}")
        for child in item["nested"]:
            path = location + "!/" + child["path"]
            occurrences.append({"path": path, "component": component, "sha256": child["sha256"], "depth": depth + 1})
            nested_occurrences(archives[child["sha256"]], path, component, depth + 1)

    def pom_licenses(data, source, seen=None):
        seen = set() if seen is None else seen
        try:
            pom = ET.fromstring(data)
        except ET.ParseError:
            return [], [f"Invalid POM: {source}"]
        licenses = [{"name": item.findtext("{*}name", ""), "url": item.findtext("{*}url", ""),
                     "evidence": source} for item in pom.findall("{*}licenses/{*}license")]
        if licenses:
            return licenses, []
        parent = pom.find("{*}parent")
        if parent is None:
            return [], []
        parts = [parent.findtext("{*}" + key, "") for key in ("groupId", "artifactId", "version")]
        if not all(parts) or any("${" in part or "/" in part or "\\" in part for part in parts):
            return [], [f"Unresolved parent POM: {source}"]
        group, artifact, version = parts
        identity = ":".join(parts)
        if identity in seen or len(seen) >= 20:
            return [], [f"Cyclic/deep parent POM: {identity}"]
        seen.add(identity)
        path = cache / group.replace(".", "/") / artifact / version / f"{artifact}-{version}.pom"
        if not path.resolve().is_relative_to(cache.resolve()) or not path.is_file():
            return [], [f"Parent POM unavailable offline: {identity}"]
        return pom_licenses(path.read_bytes(), "local Maven cache: " + identity, seen)

    def inspect(data, location, component, depth=0):
        if depth > 8:
            raise ValueError(f"Excessive nested JAR depth: {location}")
        identity = digest(data)
        occurrences.append({"path": location, "component": component, "sha256": identity, "depth": depth})
        if identity in archives:
            nested_occurrences(archives[identity], location, component, depth)
            return
        item = {"sha256": identity, "bytes": len(data), "examplePath": location,
                "coordinates": [], "declaredLicenses": [], "notices": [], "nested": [],
                "issues": [], "licenseReviewStatus": "unreviewed"}
        archives[identity] = item
        with zipfile.ZipFile(io.BytesIO(data)) as jar:
            for entry in jar.infolist():
                name = entry.filename
                if entry.is_dir():
                    continue
                if name.endswith(".jar"):
                    child = jar.read(entry)
                    item["nested"].append({"path": name, "sha256": digest(child)})
                    inspect(child, location + "!/" + name, component, depth + 1)
                elif name.endswith("pom.properties") and "/maven/" in name:
                    properties = dict(re.findall(r"^(groupId|artifactId|version)\s*=\s*(.+)$",
                                                 jar.read(entry).decode("utf-8", errors="replace"), re.M))
                    if all(properties.get(key) for key in ("groupId", "artifactId", "version")):
                        item["coordinates"].append({**{k: v.strip() for k, v in properties.items()}, "evidence": name})
                elif name.endswith("pom.xml") and "/maven/" in name:
                    licenses, issues = pom_licenses(jar.read(entry), name)
                    item["declaredLicenses"].extend(licenses)
                    item["issues"].extend(issues)
                elif re.search(r"(^|/)(license|notice|copying|copyright|dependencies)([^/]*)$", name, re.I) \
                        and not name.endswith((".class", ".java")):
                    body = jar.read(entry)
                    if not body:
                        continue
                    relative = "notices/" + digest(body) + ".txt"
                    (destination / relative).write_bytes(body)
                    item["notices"].append({"entry": name, "file": relative, "sha256": digest(body)})
        if not item["declaredLicenses"]:
            item["issues"].append("No embedded/cached POM license declaration resolved")
        if not item["notices"]:
            item["issues"].append("No embedded license/notice text found")

    paths = sorted(package.rglob("*.jar"))
    for path in paths:
        if not path.resolve().is_relative_to(package):
            raise ValueError(f"External JAR symlink: {path}")
        relative = path.relative_to(package).as_posix()
        inspect(path.read_bytes(), relative, relative.split("/")[0])
    if not paths:
        raise ValueError("No JAR files in package")
    result = {"schemaVersion": 1, "package": package.name,
              "scope": "Java archives and embedded metadata; relationships describe JAR containment, not a complete runtime dependency graph. Native libraries and unlabelled shaded code require separate review.",
              "licenseReviewComplete": False, "networkUsed": False,
              "outerJarCounts": dict(collections.Counter(p.relative_to(package).parts[0] for p in paths)),
              "uniqueArchives": len(archives), "archives": list(archives.values()), "occurrences": occurrences}
    (destination / "java-inventory.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    components = []
    for item in archives.values():
        component = {"type": "library", "bom-ref": "urn:sha256:" + item["sha256"],
                     "name": item["examplePath"].split("!/")[-1].rsplit("/", 1)[-1],
                     "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                     "properties": [{"name": "massdb:license-review", "value": "unreviewed"},
                                    {"name": "massdb:archive-path", "value": item["examplePath"]},
                                    {"name": "massdb:declared-license-evidence", "value": json.dumps(item["declaredLicenses"])}]}
        if len(item["coordinates"]) == 1:
            coord = item["coordinates"][0]
            if all("${" not in coord[key] for key in ("groupId", "artifactId", "version")):
                component.update({"group": coord["groupId"], "name": coord["artifactId"], "version": coord["version"],
                                  "purl": "pkg:maven/" + quote(coord["groupId"], safe=".") + "/"
                                  + quote(coord["artifactId"], safe="") + "@" + quote(coord["version"], safe="")})
        components.append(component)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": {"type": "application", "name": "MassDB SQL Java distribution"},
                        "properties": [{"name": "massdb:scope", "value": result["scope"]},
                                       {"name": "massdb:license-review-complete", "value": "false"}]},
           "components": components,
           "dependencies": [{"ref": "urn:sha256:" + item["sha256"],
                             "dependsOn": sorted({"urn:sha256:" + child["sha256"] for child in item["nested"]})}
                            for item in archives.values()]}
    provenance = package / "PRODUCT-PROVENANCE.json"
    if provenance.is_file():
        data = json.loads(read_text(provenance))
        bom["metadata"]["component"].update({"name": data["productName"], "version": data["productVersion"]})
        bom["metadata"]["properties"].extend([
            {"name": "massdb:upstream-source-version", "value": data["upstream"]["sourceVersion"]},
            {"name": "massdb:upstream-source-commit", "value": data["upstream"]["sourceCommit"]},
        ])
    (destination / "java-sbom.cdx.json").write_text(json.dumps(bom, ensure_ascii=False, indent=2) + "\n")
    pending = [item for item in archives.values() if item["issues"]]
    summary = {"outerJarCounts": result["outerJarCounts"], "uniqueArchives": len(archives),
               "archivesWithEvidenceGaps": len(pending), "licenseReviewComplete": False}
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (destination / "review-queue.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sha256", "example_path", "coordinates", "declared_license_names", "evidence_gaps", "review_status"])
        for item in archives.values():
            writer.writerow([item["sha256"], item["examplePath"],
                             "; ".join(":".join(c[k] for k in ("groupId", "artifactId", "version")) for c in item["coordinates"]),
                             "; ".join(sorted({c["name"] for c in item["declaredLicenses"]})),
                             "; ".join(item["issues"]), "unreviewed"])
    print(json.dumps(summary))


def check_ui_toolchain():
    package = json.loads(read_text(ROOT / "ui/package.json"))
    for command in ("node", "npm"):
        required = package["engines"][command]
        match = re.fullmatch(r">=(\d+)\.(\d+)\.(\d+) <(\d+)", required)
        if not match:
            raise ValueError(f"Unsupported {command} constraint in ui/package.json: {required}")
        try:
            found = subprocess.check_output([command, "--version"], text=True, stderr=subprocess.STDOUT).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError(f"UI build requires {command} {required}; set MASSDB_UI_NODE_DIR or PATH") from exc
        version = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", found)
        if not version or not (tuple(map(int, match.groups()[:3])) <= tuple(map(int, version.groups()))
                               < (int(match[4]), 0, 0)):
            raise ValueError(f"UI build requires {command} {required}; found {found}. "
                             "Set MASSDB_UI_NODE_DIR or build with docker/compilation/Dockerfile.ui "
                             "and supply CUSTOM_UI_DIST.")


def mariadb_source(data):
    jdbc = data["mariadb"]
    name = f"mariadb-connector-j-{jdbc['version']}.tar.gz"
    source = Path(os.environ["MASSDB_MARIADB_SOURCE_ARCHIVE"]) if os.environ.get("MASSDB_MARIADB_SOURCE_ARCHIVE") \
        else ROOT / "dist/sources" / name
    if not source.is_file():
        raise ValueError(f"MariaDB source archive is missing: {source}. Restore dist/sources/{name} "
                         "or set MASSDB_MARIADB_SOURCE_ARCHIVE to the matching local archive. "
                         "FE notice assembly does not download files.")
    if digest(source.read_bytes()) != jdbc["sourceSha256"]:
        raise ValueError(f"MariaDB source SHA256 mismatch: {source}; expected {jdbc['sourceSha256']}")
    return source


def metadata():
    data = json.loads(read_text(ROOT / "dist/product-provenance.json"))
    script = read_text(ROOT / "gensrc/script/gen_build_version.sh")
    values = {}
    for field in ("PREFIX", "MAJOR", "MINOR", "PATCH", "HOTFIX", "RC_VERSION"):
        key = "DORIS_BUILD_VERSION_" + field
        match = re.search(r'\$\{' + key + r'-([^}\n]+)\}', script)
        if not match:
            raise ValueError(f"Cannot resolve {key} from version script")
        values[field] = os.environ.get(key, match.group(1).strip('"'))
    version = f"{values['PREFIX']}-{values['MAJOR']}.{values['MINOR']}.{values['PATCH']}"
    if int(values["HOTFIX"]) > 0:
        version += "." + values["HOTFIX"]
    if values["RC_VERSION"]:
        version += "-" + values["RC_VERSION"]
    data["productVersion"] = version
    data.update(source_identity())
    pom = ET.parse(ROOT / "fe/pom.xml")
    jdbc_version = pom.findtext("{*}properties/{*}mariadb-java-client.version")
    if jdbc_version != data["mariadb"]["version"]:
        raise ValueError("MariaDB POM version differs from reviewed copyright/source metadata")
    return data


def notice_files():
    data = metadata()
    notices = read_text(ROOT / "NOTICE.txt")
    distribution = read_text(ROOT / "dist/NOTICE-dist.txt")
    if distribution.strip() not in notices:
        notices += "\n\nDistribution component notices\n\n" + distribution
    files = {
        "LICENSE.txt": read_text(ROOT / "dist/LICENSE-dist.txt"),
        "NOTICE.txt": notices,
        "MODIFICATIONS.txt": read_text(ROOT / "MODIFICATIONS.md"),
        "MARIADB-NOTICE.txt": "\n".join([
            f"{data['mariadb']['name']} {data['mariadb']['version']}",
            *data["mariadb"]["copyrights"],
            "The FE uses this library. The library and its use are covered by",
            "GNU LGPL version 2.1 or later. See licenses/LICENSE-LGPL.txt.",
            "",
        ]),
        "SOURCE-ACCESS.txt": (
            "MassDB SQL source and relinking material access\n\n"
            "FE: consult legal/FE-SOURCE-ACCESS.txt in the FE installation or its companion\n"
            "materials. MariaDB source archives belong to that distribution.\n\n"
            "BE/Cloud: source or relinking obligations depend on code actually included\n"
            "in the platform binary. Consult the matching distribution's dependency\n"
            "evidence and material instructions; this index does not assert that every\n"
            "BE build contains LGPL native code or needs relinking objects.\n\n"
            "These instructions are an index, not a written offer. Source archives and\n"
            "BE relinking objects are not served as FE static web resources.\n\n"
            "FE 对应源码的位置见安装包内 legal/FE-SOURCE-ACCESS.txt。BE/Cloud 是否需要\n"
            "额外源码或重链接材料，以对应平台二进制实际纳入的组件和许可为准；本索引\n"
            "不宣称所有 BE 构建均需要此类材料，不证明材料已交付，也不构成书面要约。\n"
        ),
    }
    for path in sorted((ROOT / "dist/licenses").rglob("*")):
        if path.is_file():
            files["licenses/" + path.relative_to(ROOT / "dist/licenses").as_posix()] = read_text(path)
    files["licenses/LICENSE-Apache-2.0.txt"] = read_text(ROOT / "LICENSE.txt")
    return {"metadata": data, "files": files}


def check_ui(directory):
    root = directory.resolve()
    manifest = json.loads(read_text(root / "legal/manifest.json"))
    if manifest.get("schemaVersion") != 1:
        raise ValueError("Unsupported legal manifest")
    required = {"legal/LICENSE.txt", "legal/NOTICE.txt", "legal/THIRD-PARTY-NOTICES.txt",
                "legal/MARIADB-NOTICE.txt", "legal/SOURCE-ACCESS.txt",
                "legal/components.json", "legal/sbom.cdx.json", "legal/MODIFICATIONS.txt",
                "legal/licenses/LICENSE-LGPL.txt"}
    paths = {entry["path"] for entry in manifest["files"]}
    if not required.issubset(paths):
        raise ValueError(f"Missing legal resources: {sorted(required - paths)}")
    for entry in manifest["files"] + manifest["assets"]:
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"Missing or unsafe resource: {entry['path']}")
        payload = path.read_bytes()
        if not payload or digest(payload) != entry["sha256"]:
            raise ValueError(f"Resource hash mismatch: {entry['path']}")
        if entry["path"].startswith("legal/") and b"<html" in payload[:1000].lower():
            raise ValueError(f"HTML fallback instead of a legal resource: {entry['path']}")
    actual_assets = {p.relative_to(root).as_posix() for p in root.rglob("*")
                     if p.is_file() and not p.relative_to(root).as_posix().startswith("legal/")}
    if actual_assets != {entry["path"] for entry in manifest["assets"]}:
        raise ValueError("UI assets differ from the reviewed bundle inventory")
    inputs = notice_files()
    for name, text in inputs["files"].items():
        path = root / "legal" / name
        if "legal/" + name not in paths or not path.is_file() or path.read_bytes() != text.encode("utf-8"):
            raise ValueError(f"Stale or omitted repository notice: {name}")
    current = inputs["metadata"]
    for key, value in current.items():
        if manifest["metadata"].get(key) != value:
            raise ValueError(f"Stale product notices: {key}")
    if not manifest.get("components"):
        raise ValueError("Missing bundled component inventory")
    components = json.loads(read_text(root / "legal/components.json"))
    if manifest["components"] != components:
        raise ValueError("Component inventory differs from the legal manifest")
    return manifest


def install_fe(destination, ui_dist=None):
    data = metadata()
    source = mariadb_source(data)
    legal = destination / "legal"
    jdbc = data["mariadb"]
    jar = destination / "lib" / f"mariadb-java-client-{jdbc['version']}.jar"
    if not jar.is_file():
        raise ValueError(f"Expected FE runtime dependency is missing: {jar}")
    if digest(jar.read_bytes()) != jdbc["jarSha256"]:
        raise ValueError("FE MariaDB JAR differs from reviewed artifact; review its matching source")
    if ui_dist:
        check_ui(ui_dist)
        shutil.copytree(ui_dist / "legal", legal, dirs_exist_ok=True)
    else:
        for name, text in notice_files()["files"].items():
            path = legal / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    source_name = f"mariadb-connector-j-{jdbc['version']}.tar.gz"
    (legal / "sources").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, legal / "sources" / source_name)
    (legal / "FE-SOURCE-ACCESS.txt").write_text(
        f"MariaDB Connector/J {jdbc['version']}\n\n"
        f"Corresponding source: legal/sources/{source_name}\n"
        f"Source SHA256: {jdbc['sourceSha256']}\n"
        f"Source origin: {jdbc['sourceUrl']}\n"
        f"Runtime JAR: lib/{jar.name}\n"
        f"JAR SHA256: {digest(jar.read_bytes())}\n\n"
        "The source archive includes the upstream build files. Retain the LGPL\n"
        "license and copyright notices when modifying the library. To replace the\n"
        "library, stop FE, back up the original JAR, install an interface-compatible\n"
        "modified JAR in lib/ without leaving duplicate driver versions, and restart\n"
        "FE. Verify SQL execution and retain your modified library's source.\n\n"
        "This source delivery does not include BE relinking materials. Consult the\n"
        "matching BE distribution separately. It is not a written offer.\n",
        encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--metadata", action="store_true")
    commands.add_argument("--inputs", action="store_true")
    commands.add_argument("--check-ui", type=Path)
    commands.add_argument("--check-fe-jar", type=Path)
    commands.add_argument("--copy-ui-notices", type=Path, metavar="UI_DIST")
    commands.add_argument("--install-fe", type=Path, metavar="FE_DIRECTORY")
    commands.add_argument("--check-fe-inputs", action="store_true", help="Check provenance and local source inputs without network access")
    commands.add_argument("--check-ui-toolchain", action="store_true", help="Check Node/npm before installing dependencies")
    commands.add_argument("--inventory-java-package", type=Path, metavar="PACKAGE", help="Inventory JARs and nested notices offline; requires --destination")
    commands.add_argument("--check-release-provenance", action="store_true", help="Require a known commit and clean source state for release")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--ui-dist", type=Path)
    args = parser.parse_args()
    if args.inventory_java_package:
        if not args.destination:
            parser.error("--inventory-java-package requires --destination")
        inventory_java_package(args.inventory_java_package, args.destination)
    elif args.check_release_provenance:
        check_release_provenance()
        print("Release source reference verified")
    elif args.check_ui_toolchain:
        check_ui_toolchain()
        print("UI Node/npm toolchain verified")
    elif args.check_fe_inputs:
        mariadb_source(metadata())
        print("FE notice inputs verified (local files only)")
    elif args.metadata:
        print(json.dumps(metadata(), ensure_ascii=False))
    elif args.inputs:
        print(json.dumps(notice_files(), ensure_ascii=False))
    elif args.install_fe:
        install_fe(args.install_fe, args.ui_dist)
        print("FE notices and corresponding MariaDB source installed")
    elif args.check_fe_jar:
        with tempfile.TemporaryDirectory(prefix="massdb-ui-notices-") as directory:
            target = Path(directory)
            with zipfile.ZipFile(args.check_fe_jar) as archive:
                for entry in archive.infolist():
                    if not entry.filename.startswith("static/") or entry.is_dir():
                        continue
                    path = (target / entry.filename[len("static/"):]).resolve()
                    if not path.is_relative_to(target):
                        raise ValueError("Unsafe static resource path in FE JAR")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.read(entry))
            check_ui(target)
        print("FE JAR product notices verified")
    else:
        check_ui(args.check_ui or args.copy_ui_notices)
        if args.copy_ui_notices:
            if not args.destination:
                parser.error("--copy-ui-notices requires --destination")
            shutil.copytree(args.copy_ui_notices / "legal", args.destination / "legal", dirs_exist_ok=True)
        print("Product notices and UI asset inventory verified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, ET.ParseError) as exc:
        sys.exit(f"Product notices: {exc}")
