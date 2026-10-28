#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Check a MassDB SQL Python runtime before it ships with the BE (prototype).

Takes the runtime tarball or an unpacked python-runtime/ directory and checks what BEs and target
hosts rely on: the env-root layout BE scans at startup (python_env_mode = conda), ELF compatibility
with the target glibc and 64 KiB page kernels, imports, a real UDF call through
be/src/udf/python/python_server.py, and the license inventory. Exits 1 when an error is found.
"""

import sys

if sys.version_info < (3, 9):
    sys.exit("check-python-runtime.py requires Python 3.9 or newer")

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import email.parser
import hashlib
import json
import mmap
import os
from pathlib import Path
import queue
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MACHINES = {"aarch64": 183, "x86_64": 62}
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NEEDED, DT_STRTAB, DT_SONAME, DT_RPATH, DT_RUNPATH = 1, 5, 14, 15, 29
DT_VERNEED, DT_VERNEEDNUM = 0x6ffffffe, 0x6fffffff
# glibc, the C++ runtime and the dynamic loaders: everything else must ship inside the runtime.
SYSTEM_LIBRARIES = {
    "libc.so.6", "libm.so.6", "libdl.so.2", "librt.so.1", "libpthread.so.0", "libutil.so.1", "libresolv.so.2",
    "libnsl.so.1", "libcrypt.so.1", "libgcc_s.so.1", "libstdc++.so.6", "ld-linux-aarch64.so.1",
    "ld-linux-x86-64.so.2",
}
RANK = {"allow": 0, "review": 1, "unknown": 2, "deny": 3}
SERVER_READY = "Start python server successfully"
STATIC_PROBE = r'''
import json, sys
found = {"python": sys.version.split()[0]}
probes = {
    "OpenSSL": "import ssl; value = ssl.OPENSSL_VERSION",
    "SQLite": "import sqlite3; value = sqlite3.sqlite_version",
    "zlib": "import zlib; value = zlib.ZLIB_RUNTIME_VERSION",
    "bzip2": "import bz2; value = 'linked'",
    "XZ": "import lzma; value = 'linked'",
    "libffi": "import ctypes; value = 'linked'",
    "mpdecimal": "import decimal; value = decimal.__libmpdec_version__",
    "Expat": "import pyexpat; value = pyexpat.EXPAT_VERSION",
    "readline": "import readline; value = 'libedit' if 'libedit' in (readline.__doc__ or '') "
                "else 'GNU readline ' + str(readline._READLINE_LIBRARY_VERSION)",
    "ncurses": "import _curses; value = 'linked'",
    "Tcl/Tk": "import tkinter; value = str(tkinter.TclVersion)",
    "uuid": "import _uuid; value = 'linked'",
}
for name, code in probes.items():
    scope = {}
    try:
        exec(code, scope)
        found[name] = scope["value"]
    except Exception:
        pass
print(json.dumps(found))
'''
UDF_CLIENT = r'''
import base64, json, sys
import pyarrow as pa
from pyarrow import flight

socket_path, version = sys.argv[1], sys.argv[2]


def call(function_id, symbol, code, arrays, output_type):
    inputs = pa.schema([(f"c{index}", array.type) for index, array in enumerate(arrays)])
    command = {"id": function_id, "name": symbol, "symbol": symbol, "location": "", "udf_load_type": 0,
               "client_type": 0, "runtime_version": version, "always_nullable": True,
               "inline_code": base64.b64encode(code.encode()).decode(),
               "input_types": base64.b64encode(inputs.serialize().to_pybytes()).decode(),
               "return_type": base64.b64encode(pa.schema([("r", output_type)]).serialize().to_pybytes()).decode()}
    client = flight.connect(f"grpc+unix://{socket_path}")
    try:
        writer, reader = client.do_exchange(flight.FlightDescriptor.for_command(json.dumps(command)))
        writer.begin(inputs)
        writer.write_batch(pa.RecordBatch.from_arrays(arrays, schema=inputs))
        writer.done_writing()
        result = reader.read_all()
        writer.close()
        return result.column(0).to_pylist()
    finally:
        client.close()


print(json.dumps({
    "scalar": call(1, "add_one", "def add_one(x):\n    return None if x is None else x + 1\n",
                   [pa.array([1, None, 3], pa.int64())], pa.int64()),
    "vectorized": call(2, "scale", "import numpy as np\nimport pandas as pd\n\n"
                       "def scale(a: pd.Series, b: pd.Series) -> pd.Series:\n    return a * b + np.float64(0.5)\n",
                       [pa.array([1.5, 2.0], pa.float64()), pa.array([2.0, 3.0], pa.float64())], pa.float64()),
}))
'''
UDF_EXPECTED = {"scalar": [2, None, 4], "vectorized": [3.5, 6.5]}


class Report:
    def __init__(self):
        self.findings = []
        self.facts = {}

    def add(self, level, check, message, items=None, keep_order=False):
        finding = {"level": level, "check": check, "message": message}
        if items:
            finding["items"] = list(items) if keep_order else sorted(items)
        self.findings.append(finding)

    def count(self, level):
        return sum(1 for finding in self.findings if finding["level"] == level)


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def version_tuple(text):
    return tuple(int(part) for part in text.split("."))


def clean_env(home, extra=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONNOUSERSITE": "1"}
    env.update(extra or {})
    return env


def short_tempdir(prefix):
    """Unix socket paths are limited to 107 bytes; keep socket directories short."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    if len(str(path)) > 60:
        path.rmdir()
        path = Path(tempfile.mkdtemp(prefix=prefix, dir="/tmp"))
    return path


# ---------------------------------------------------------------- ELF

def parse_elf(path):
    """PT_LOAD alignments, DT_NEEDED/SONAME/RUNPATH and symbol-version needs of a 64-bit LE ELF."""
    with open(path, "rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if data[4] != 2 or data[5] != 1:
            return {"unsupported": True}
        e_type, e_machine, _, _, e_phoff, _, _, _, e_phentsize, e_phnum = struct.unpack_from("<HHIQQQIHHH", data, 16)
        segments = [struct.unpack_from("<IIQQQQQQ", data, e_phoff + index * e_phentsize) for index in range(e_phnum)]
        loads = [segment for segment in segments if segment[0] == PT_LOAD]
        info = {"machine": e_machine, "type": e_type, "aligns": sorted({segment[7] for segment in loads}),
                "needed": [], "soname": None, "runpath": [], "versions": {}}

        def file_offset(address):
            for _, _, offset, vaddr, _, filesz, _, _ in loads:
                if vaddr <= address < vaddr + filesz:
                    return address - vaddr + offset
            return None

        dynamic = next((segment for segment in segments if segment[0] == PT_DYNAMIC), None)
        if dynamic is None:
            return info
        entries = []
        for position in range(dynamic[2], dynamic[2] + dynamic[5], 16):
            tag, value = struct.unpack_from("<qQ", data, position)
            if tag == 0:
                break
            entries.append((tag, value))
        tags = dict(entries)
        strtab = file_offset(tags.get(DT_STRTAB, -1))
        if strtab is None:
            return info

        def string(offset):
            start = strtab + offset
            return data[start:data.find(b"\0", start)].decode("utf-8", "replace")

        for tag, value in entries:
            if tag == DT_NEEDED:
                info["needed"].append(string(value))
            elif tag == DT_SONAME:
                info["soname"] = string(value)
            elif tag in (DT_RPATH, DT_RUNPATH):
                info["runpath"] += [item for item in string(value).split(":") if item]
        position = file_offset(tags[DT_VERNEED]) if DT_VERNEED in tags else None
        for _ in range(tags.get(DT_VERNEEDNUM, 0) if position is not None else 0):
            _, count, library, aux, following = struct.unpack_from("<HHIII", data, position)
            names = info["versions"].setdefault(string(library), set())
            entry = position + aux
            for _ in range(count):
                _, _, _, name, step = struct.unpack_from("<IHHII", data, entry)
                names.add(string(name))
                if not step:
                    break
                entry += step
            if not following:
                break
            position += following
        return info


def elf_files(root):
    for directory, names, files in os.walk(root):
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or path.stat().st_size < 64:
                continue
            with open(path, "rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    yield path


def newest(versions, prefix):
    matched = [version_tuple(name[len(prefix) + 1:]) for name in versions
               if re.fullmatch(re.escape(prefix) + r"_\d+(?:\.\d+)*", name)]
    return max(matched) if matched else None


def check_elf(root, arch, target, report):
    parsed = {}
    for path in elf_files(root):
        parsed[path.relative_to(root).as_posix()] = parse_elf(path)
    provided = {Path(name).name for name in parsed} | {info["soname"] for info in parsed.values() if info.get("soname")}
    wrong_machine, misaligned, unsupported, glibc_new = [], [], [], []
    external = {}
    maxima = {"GLIBC": None, "GLIBCXX": None, "CXXABI": None, "GCC": None}
    glibc_limit = version_tuple(target["glibc"])
    # libstdc++ exports both symbol families; an old libstdc++ can miss either (numpy needs CXXABI_1.3.9 first).
    cxx_limits = {prefix: version_tuple(target[prefix.lower()]) for prefix in ("GLIBCXX", "CXXABI")
                  if target.get(prefix.lower())}
    cxx_new = {prefix: [] for prefix in cxx_limits}
    for name, info in parsed.items():
        if info.get("unsupported"):
            unsupported.append(name)
            continue
        if info["machine"] != MACHINES[arch]:
            wrong_machine.append(name)
        if any(align < target["minLoadAlign"] or align % target["minLoadAlign"] for align in info["aligns"]):
            misaligned.append(f"{name} (PT_LOAD align {', '.join(hex(align) for align in info['aligns'])})")
        versions = set().union(*info["versions"].values()) if info["versions"] else set()
        for prefix in maxima:
            found = newest(versions, prefix)
            if found and (maxima[prefix] is None or found > maxima[prefix]):
                maxima[prefix] = found
        glibc = newest(versions, "GLIBC")
        if glibc and glibc > glibc_limit:
            glibc_new.append(f"{name} (GLIBC_{'.'.join(map(str, glibc))})")
        for prefix, limit in cxx_limits.items():
            found = newest(versions, prefix)
            if found and found > limit:
                cxx_new[prefix].append(f"{name} ({prefix}_{'.'.join(map(str, found))})")
        origin = str((root / name).parent)
        for library in info["needed"]:
            if "/" in library and Path(library.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)).exists():
                continue
            if library not in provided:
                external.setdefault(library, []).append(name)
    report.facts["elfFiles"] = len(parsed)
    report.facts["newestSymbolVersions"] = {key: ".".join(map(str, value)) for key, value in maxima.items() if value}
    report.facts["systemLibraries"] = sorted(external)
    if wrong_machine:
        report.add("error", "elf", f"{len(wrong_machine)} ELF files are not built for {arch}", wrong_machine)
    if misaligned:
        report.add("error", "elf", f"{len(misaligned)} ELF files have PT_LOAD alignment that is not a multiple of "
                   f"{target['minLoadAlign']:#x}; glibc refuses to load them on kernels with that page size",
                   misaligned)
    if glibc_new:
        report.add("error", "elf", f"{len(glibc_new)} ELF files need a glibc newer than the target {target['glibc']}",
                   glibc_new)
    for prefix, items in cxx_new.items():
        if items:
            report.add("error", "elf",
                       f"{len(items)} ELF files need a libstdc++ newer than {prefix}_{target[prefix.lower()]}", items)
    if unsupported:
        report.add("warning", "elf", f"{len(unsupported)} ELF files are not 64-bit little-endian and were not checked",
                   unsupported)
    unusual = {library: users for library, users in external.items() if library not in SYSTEM_LIBRARIES}
    if unusual:
        report.add("warning", "elf", "Libraries the target OS must provide besides glibc and libstdc++",
                   [f"{library} (needed by {len(users)} files, e.g. {users[0]})" for library, users in unusual.items()])
    newest_versions = report.facts["newestSymbolVersions"]
    report.add("info", "elf", f"Checked {len(parsed)} ELF files: newest "
               + ", ".join(f"{prefix}_{newest_versions.get(prefix, '-')}" for prefix in ("GLIBC", "GLIBCXX", "CXXABI"))
               + ("" if len(cxx_limits) == 2 else
                  "; set target.glibcxx and target.cxxabi to the oldest target libstdc++ to enforce them"))


# ---------------------------------------------------------------- layout

def check_symlinks(root, report):
    absolute, broken, escaping = [], [], []
    base = root.resolve()
    for directory, names, files in os.walk(root):
        for name in names + files:
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if os.path.isabs(os.readlink(path)):
                absolute.append(relative)
            elif not path.exists():
                broken.append(relative)
            elif not path.resolve().is_relative_to(base):
                escaping.append(relative)
    for items, what in ((absolute, "absolute"), (broken, "broken"), (escaping, "outside the runtime")):
        if items:
            report.add("error", "symlinks", f"{len(items)} {what} symlinks (the package assembly rejects them)", items)


def python_full_version(python, env):
    """What BE parses from `python --version` (python_env.cpp: ^Python (\\d+\\.\\d+\\.\\d+))."""
    try:
        result = subprocess.run([str(python), "--version"], env=env, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)
    match = re.match(r"^Python (\d+\.\d+\.\d+)", result.stdout)
    return (match.group(1), None) if match else (None, (result.stdout + result.stderr).strip())


def check_layout(root, manifest, env, report):
    envs = root / "envs"
    if not envs.is_dir():
        report.add("error", "layout", "envs/ is missing: BE scans <python_conda_root_path>/envs/*")
        return None
    found = {}
    for entry in sorted(envs.iterdir()):
        if not entry.is_dir():
            report.add("warning", "layout", f"envs/{entry.name} is not a directory; BE ignores it")
            continue
        python = entry / "bin" / "python"
        if not (python.is_file() and os.access(python, os.X_OK)):
            report.add("error", "layout",
                       f"envs/{entry.name}/bin/python is missing or not executable: BE exits at startup")
            continue
        version, problem = python_full_version(python, env)
        if not version:
            report.add("error", "layout",
                       f"envs/{entry.name}: `python --version` failed, BE exits at startup: {problem}")
            continue
        site = entry / "lib" / f"python{'.'.join(version.split('.')[:2])}" / "site-packages"
        if not site.is_dir():
            report.add("error", "layout", f"envs/{entry.name}: {site.relative_to(root)} is missing")
            continue
        found[entry.name] = (version, python, site)
    report.facts["envs"] = {name: version for name, (version, _, _) in found.items()}
    expected = manifest.get("env", {}).get("name") if manifest else None
    if manifest and expected not in found:
        report.add("error", "layout", f"MANIFEST.json env {expected} is not a usable env")
        return None
    if manifest and found[expected][0] != manifest["python"]["version"]:
        report.add("error", "layout", f"envs/{expected} reports Python {found[expected][0]}, "
                   f"MANIFEST.json says {manifest['python']['version']}")
    if len(found) > 1:
        report.add("info", "layout", f"{len(found)} envs: BE offers each version to runtime_version "
                   f"({', '.join(version for version, _, _ in found.values())})")
    if not found:
        return None
    return found[expected] if expected else next(iter(found.values()))


# ---------------------------------------------------------------- distributions and licenses

def distributions(site):
    parser = email.parser.HeaderParser()
    result = {}
    for info in sorted(site.glob("*.dist-info")):
        metadata = parser.parsestr((info / "METADATA").read_text(encoding="utf-8", errors="replace"))
        record = []
        if (info / "RECORD").is_file():
            with open(info / "RECORD", newline="", encoding="utf-8") as stream:
                record = [row for row in csv.reader(stream) if row]
        top_level = []
        if (info / "top_level.txt").is_file():
            top_level = [line.strip() for line in (info / "top_level.txt").read_text().splitlines()
                         if line.strip() and "/" not in line]
        result[canonical(metadata["Name"])] = {
            "name": canonical(metadata["Name"]),
            "version": metadata["Version"],
            "expression": metadata.get("License-Expression"),
            "license": metadata.get("License"),
            "classifiers": [value.split("::")[-1].strip() for value in metadata.get_all("Classifier") or []
                            if value.startswith("License ::") and value.strip() != "License :: OSI Approved"],
            "record": record,
            "topLevel": top_level,
        }
    return result


def module_names(distribution, site=None):
    """Importable top-level names; top_level.txt can list modules a package has since moved."""
    names = set(distribution["topLevel"])
    for row in [] if names else distribution["record"]:
        first = row[0].split("/", 1)[0]
        if first.endswith((".dist-info", ".data", ".libs", ".pth")) or first in ("..", "__pycache__", ""):
            continue
        if "/" in row[0]:
            names.add(first)
        elif first.endswith(".py"):
            names.add(first[:-3])
        elif ".so" in first:
            names.add(first.split(".", 1)[0])
    if site:
        names = {name for name in names if (site / name).is_dir() or (site / f"{name}.py").is_file()
                 or any(site.glob(f"{name}.*.so")) or (site / f"{name}.so").is_file()}
    return sorted(names)


def classify(text, policy):
    for verdict in ("deny", "review", "allow"):
        if any(re.search(pattern, text, re.I) for pattern in policy[verdict]):
            return verdict
    return "unknown"


def license_verdict(distribution, policy, overrides):
    override = overrides.get(distribution["name"])
    if override:
        return classify(override["license"], policy), f"override: {override['license']} ({override['reason']})"
    if distribution["expression"]:
        expression = distribution["expression"]
        alternatives = [part.strip(" ()") for part in re.split(r"\s+OR\s+", expression)]
        verdict = min((max((classify(item.strip(" ()"), policy) for item in re.split(r"\s+AND\s+", alternative)),
                           key=RANK.get) for alternative in alternatives), key=RANK.get)
        return verdict, expression
    if distribution["classifiers"]:
        verdicts = [classify(item, policy) for item in distribution["classifiers"]]
        verdict = min(verdicts, key=RANK.get)
        if "deny" in verdicts and verdict == "allow":
            verdict = "review"
        return verdict, "; ".join(distribution["classifiers"])
    text = (distribution["license"] or "").strip().splitlines()
    if text and text[0].strip() and text[0].strip().upper() != "UNKNOWN":
        return classify(text[0][:200], policy), text[0][:200]
    return "unknown", "no license metadata"


def check_distributions(root, site, manifest, config, strict, report):
    dists = distributions(site)
    policy, overrides = config["licensePolicy"], config.get("licenseOverrides", {})
    if manifest:
        listed = {package["name"]: package["version"] for package in manifest["packages"]}
        installed = {name: item["version"] for name, item in dists.items()}
        if listed != installed:
            difference = sorted(f"{name}: manifest {listed.get(name)} / installed {installed.get(name)}"
                                for name in set(listed) | set(installed) if listed.get(name) != installed.get(name))
            report.add("error", "manifest", "MANIFEST.json packages differ from the installed distributions",
                       difference)
    inventory, by_verdict, vendored, missing_texts = [], {}, [], []
    sizes = {}
    for name, item in dists.items():
        verdict, basis = license_verdict(item, policy, overrides)
        by_verdict.setdefault(verdict, []).append(f"{name} {item['version']}: {basis}")
        libs = sorted({row[0] for row in item["record"] if row[0].split("/", 1)[0].endswith(".libs")})
        if libs:
            vendored.append(f"{name}: {', '.join(Path(path).name for path in libs)}")
        texts = root / "LICENSES" / f"{name}-{item['version']}"
        if not (texts.is_dir() and any(texts.rglob("*"))):
            missing_texts.append(f"{name} {item['version']}")
        sizes[name] = sum(int(row[2]) for row in item["record"] if len(row) > 2 and row[2].isdigit())
        inventory.append({"name": name, "version": item["version"], "verdict": verdict, "basis": basis,
                          "vendoredLibraries": [Path(path).name for path in libs], "installedBytes": sizes[name]})
    report.facts["distributions"] = inventory
    report.facts["largestDistributions"] = [f"{name} {size / 1048576:.1f} MiB" for name, size in
                                            sorted(sizes.items(), key=lambda pair: -pair[1])[:10]]
    if by_verdict.get("deny"):
        report.add("error", "license", "Distributions under licenses the policy denies", by_verdict["deny"])
    if by_verdict.get("review"):
        report.add("warning", "license", "Distributions whose license needs legal review", by_verdict["review"])
    if by_verdict.get("unknown"):
        report.add("error" if strict else "warning", "license",
                   "Distributions without a recognised license (add licenseOverrides after checking the text)",
                   by_verdict["unknown"])
    if missing_texts:
        report.add("error" if strict else "warning", "license", "Distributions without license text under LICENSES/",
                   missing_texts)
    if vendored:
        report.add("warning", "license", "Wheels that vendor native libraries; each library needs its own notice",
                   vendored)
    if not (root / "LICENSES").is_dir() or not any((root / "LICENSES").glob("cpython-*/LICENSE.txt")):
        report.add("error", "license", "LICENSES/cpython-*/LICENSE.txt is missing")
    return dists


# ---------------------------------------------------------------- runtime

def import_module(python, name, env):
    try:
        result = subprocess.run([str(python), "-I", "-c", "import importlib, sys; importlib.import_module(sys.argv[1])",
                                 name], env=env, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return name, "timed out after 180 s"
    if result.returncode:
        lines = (result.stderr or result.stdout).strip().splitlines()
        return name, (lines[-1] if lines else f"exit code {result.returncode}")
    return name, None


def server_smoke(python, server, version, env, report):
    workdir = short_tempdir("pyrt-")
    process = None
    try:
        child_env = dict(env, DORIS_HOME=str(workdir))
        process = subprocess.Popen([str(python), "-u", str(server), f"grpc+unix://{workdir}/udf"], env=child_env,
                                   cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True).start()
        deadline, seen, ready = time.monotonic() + 120, [], False
        while time.monotonic() < deadline and not ready:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            seen.append(line.rstrip())
            ready = line.strip() == SERVER_READY
        if not ready:
            report.add("error", "server", "python_server.py did not report readiness", seen[-20:], keep_order=True)
            return
        client = workdir / "client.py"
        client.write_text(UDF_CLIENT, encoding="utf-8")
        result = subprocess.run([str(python), "-I", str(client), f"{workdir}/udf_{process.pid}.sock", version],
                                env=child_env, capture_output=True, text=True, timeout=180)
        try:
            answer = json.loads(result.stdout.strip().splitlines()[-1]) if result.returncode == 0 else None
        except (IndexError, json.JSONDecodeError):
            answer = None
        if answer != UDF_EXPECTED:
            log_file = workdir / "log" / "python_udf_output.log"
            tail = log_file.read_text(errors="replace").splitlines()[-20:] if log_file.is_file() else []
            report.add("error", "server", f"UDF calls through python_server.py returned {answer!r}, expected "
                       f"{UDF_EXPECTED!r}", (result.stderr.strip().splitlines()[-10:] + tail) or None, keep_order=True)
            return
        report.add("info", "server", "python_server.py served an inline scalar UDF and a pandas vectorized UDF")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        shutil.rmtree(workdir, ignore_errors=True)


def check_runtime(python, version, site, dists, config, server, home, report):
    env = clean_env(home)
    required = config["requiredImports"]
    skip = config.get("importSkip", {})
    names = sorted({name for item in dists.values() for name in module_names(item, site)} - set(required) - set(skip))
    with ThreadPoolExecutor(max_workers=max(2, min(8, os.cpu_count() or 2))) as pool:
        results = dict(pool.map(lambda name: import_module(python, name, env), required + names))
    failed_required = [f"{name}: {results[name]}" for name in required if results[name]]
    failed_other = [f"{name}: {results[name]}" for name in names if results[name]]
    if failed_required:
        report.add("error", "imports", "Modules python_server.py needs cannot be imported", failed_required)
    if failed_other:
        report.add("error", "imports",
                   "Installed modules that fail to import (fix, or list in importSkip with a reason)",
                   failed_other)
    for name, reason in skip.items():
        report.add("info", "imports", f"Import of {name} skipped: {reason}")
    report.add("info", "imports", f"Imported {len(required) + len(names) - len(failed_required) - len(failed_other)}"
               f" of {len(required) + len(names)} top-level modules")
    listing = subprocess.run([str(python), "-m", "pip", "list", "--format=json"], env=env, capture_output=True,
                             text=True)
    try:
        listed = {canonical(item["name"]) for item in json.loads(listing.stdout)}
    except json.JSONDecodeError:
        listed = set()
    if listing.returncode or not set(dists) <= listed:
        report.add("error", "imports",
                   "`python -m pip list --format=json` (SHOW PYTHON PACKAGES) is incomplete or failed",
                   sorted(set(dists) - listed) or [listing.stderr.strip()[-300:]])
    probe = subprocess.run([str(python), "-I", "-c", STATIC_PROBE], env=env, capture_output=True, text=True)
    if probe.returncode == 0:
        components = json.loads(probe.stdout)
        report.facts["interpreterComponents"] = components
        linked = sorted(f"{name} {value}" for name, value in components.items() if name != "python")
        if str(components.get("readline", "")).startswith("GNU readline"):
            report.add("error", "license", "The interpreter links GNU readline (GPL-3.0); use a libedit build")
        report.add("warning", "license", "The interpreter statically links these components; ship their license texts "
                   "(python-build-standalone full archives carry them under python/licenses/)", linked)
    if server.is_file():
        server_smoke(python, server, version, env, report)
    else:
        report.add("error", "server", f"python_server.py not found: {server} (use --server-script)")


# ---------------------------------------------------------------- main

def open_input(path, workdir, report):
    """Return the python-runtime root for a tarball or a directory."""
    if path.is_file():
        checksum = path.parent / (path.name + ".sha256")
        if checksum.is_file():
            expected = checksum.read_text().split()[0]
            if digest(path) != expected:
                report.add("error", "package", f"{path.name} does not match {checksum.name}")
        else:
            report.add("warning", "package", f"No {checksum.name} next to the tarball")
        with tarfile.open(path) as tar:
            tops = {member.name.split("/", 1)[0] for member in tar}
            if len(tops) != 1:
                report.add("error", "package", f"The tarball must have one top-level directory, found {sorted(tops)}")
                return None
            tar.extractall(workdir, filter="data")
        return workdir / tops.pop()
    if (path / "envs").is_dir():
        return path
    if (path / "python-runtime" / "envs").is_dir():
        return path / "python-runtime"
    return path


def print_report(root, report):
    print(f"== Python runtime check: {root}")
    for level in ("error", "warning", "info"):
        for finding in (item for item in report.findings if item["level"] == level):
            print(f"{level.upper():7} [{finding['check']}] {finding['message']}")
            items = finding.get("items", [])
            for item in items[:15]:
                print(f"          - {item}")
            if len(items) > 15:
                print(f"          ... {len(items) - 15} more (see --report)")
    print(f"Summary: {report.count('error')} errors, {report.count('warning')} warnings")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runtime", type=Path, help="runtime tarball, or an unpacked python-runtime/ directory")
    parser.add_argument("--config", type=Path, default=HERE / "python-runtime.json",
                        help="policy (layers, imports, licenses); default: the checked-in config")
    parser.add_argument("--target-glibc", help="oldest glibc on the target BEs (default: MANIFEST/config)")
    parser.add_argument("--target-glibcxx", help="oldest libstdc++ GLIBCXX version, e.g. 3.4.19 (default: MANIFEST)")
    parser.add_argument("--target-cxxabi", help="oldest libstdc++ CXXABI version, e.g. 1.3.7 (default: MANIFEST)")
    parser.add_argument("--min-load-align", type=lambda value: int(value, 0),
                        help="required PT_LOAD alignment, 0x10000 for 64 KiB page kernels (default: MANIFEST/config)")
    parser.add_argument("--server-script", type=Path, default=ROOT / "be/src/udf/python/python_server.py",
                        help="python_server.py to smoke-test (a package's be/plugins/python_udf/python_server.py)")
    parser.add_argument("--skip-runtime", action="store_true", help="static checks only (other arch or no execution)")
    parser.add_argument("--strict-licenses", action="store_true", help="unknown licenses and missing texts are errors")
    parser.add_argument("--work-dir", type=Path, help="where to unpack a tarball (default: a temporary directory)")
    parser.add_argument("--report", type=Path, help="write the full JSON report here")
    args = parser.parse_args()

    report = Report()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    workdir = Path(tempfile.mkdtemp(prefix="pyrt-check-", dir=args.work_dir)) if args.runtime.is_file() else None
    home = Path(tempfile.mkdtemp(prefix="pyrt-home-"))
    try:
        root = open_input(args.runtime.resolve(), workdir, report)
        manifest = None
        if root and (root / "MANIFEST.json").is_file():
            manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
        elif root:
            report.add("error", "manifest", "MANIFEST.json is missing")
        if root:
            target = dict(config["target"])
            target.update({key: value for key, value in (manifest or {}).get("target", {}).items()
                           if key in target and value})
            target.update({key: value for key, value in (("glibc", args.target_glibc), ("glibcxx", args.target_glibcxx),
                                                         ("cxxabi", args.target_cxxabi),
                                                         ("minLoadAlign", args.min_load_align)) if value})
            arch = (manifest or {}).get("arch") or os.uname().machine
            report.facts.update({"runtime": str(root), "arch": arch, "target": target,
                                 "hostPageSize": os.sysconf("SC_PAGE_SIZE")})
            env = clean_env(home)
            check_symlinks(root, report)
            selected = None if args.skip_runtime else check_layout(root, manifest, env, report)
            check_elf(root, arch, target, report)
            site = None
            if selected:
                site = selected[2]
            elif manifest:
                site = root / manifest["env"]["sitePackages"]
            dists = check_distributions(root, site, manifest, config, args.strict_licenses, report) \
                if site and site.is_dir() else {}
            if selected:
                check_runtime(selected[1], selected[0], selected[2], dists, config, args.server_script.resolve(),
                              home, report)
                if report.facts["hostPageSize"] < target["minLoadAlign"]:
                    report.add("info", "runtime", f"Imports and UDF calls ran with {report.facts['hostPageSize']}-byte "
                               f"pages; {target['minLoadAlign']}-byte page kernels are covered by the ELF checks only")
            report.facts["installedBytes"] = sum(path.stat().st_size for path in root.rglob("*")
                                                 if path.is_file() and not path.is_symlink())
            report.add("info", "size", f"{report.facts['installedBytes'] / 1048576:.0f} MiB unpacked; largest "
                       "distributions:", report.facts.get("largestDistributions"), keep_order=True)
        print_report(root, report)
        if args.report:
            args.report.write_text(json.dumps({"facts": report.facts, "findings": report.findings},
                                              ensure_ascii=False, indent=2, default=sorted) + "\n", encoding="utf-8")
    finally:
        shutil.rmtree(home, ignore_errors=True)
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    sys.exit(1 if report.count("error") else 0)


if __name__ == "__main__":
    main()
