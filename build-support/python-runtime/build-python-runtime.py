#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.
"""Build the offline Python runtime used by MassDB SQL BE Python UDFs (prototype).

resolve (online, once): fetch the pinned interpreter and every wheel of the selected layers and
    write a hash-pinned lock; with --lock, fetch exactly the wheels of a committed lock instead.
    Keep the whole resolve directory: it is the only build input.
build (offline): install exactly that lock into the relocatable interpreter, laid out as a
    ``python_env_mode = conda`` root, and pack a reproducible tarball to unpack under be/lib/.
release: what build-for-release.sh runs - resolve --lock (or reuse archived inputs), build, run
    check-python-runtime.py against the packaged python_server.py and unpack into the BE component.
"""

import sys

if sys.version_info < (3, 9):
    sys.exit("build-python-runtime.py requires Python 3.9 or newer")

import argparse
import base64
import csv
from datetime import datetime, timezone
import email.parser
import gzip
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARCHES = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}
# Same relocatable launcher python-build-standalone uses for its own bin/pip.
TRAMPOLINE = "#!/bin/sh\n'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")/{python}\" \"$0\" \"$@\"\n' '''\n"
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", re.I)
PROXY_VARIABLES = ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
LOCK_HEADER = re.compile(r"^# python (\S+) (\S+); target glibc (\S+); layers (.+)$", re.M)
LOCK_ENTRY = re.compile(r"^(\S+)==(\S+) \\\n +--hash=sha256:([0-9a-f]{64})$", re.M)


def log(message):
    print(f"[python-runtime] {message}", flush=True)


def download(url, target, timeout, hint):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response, open(target, "wb") as stream:
            shutil.copyfileobj(response, stream)
    except (urllib.error.URLError, OSError) as error:
        Path(target).unlink(missing_ok=True)
        raise SystemExit(f"Cannot download {url}: {getattr(error, 'reason', error)}. {hint}")


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(spec):
    return canonical(re.split(r"[<>=!~\[;\s]", spec.strip(), maxsplit=1)[0])


def host_arch():
    machine = platform.machine().lower()
    if machine not in ARCHES:
        raise SystemExit(f"Unsupported build host architecture: {machine}")
    return ARCHES[machine]


def clean_env(home):
    """Child environment without PYTHON*/PIP*/LD_* leakage from the operator shell."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONNOUSERSITE": "1"}
    env.update({key: os.environ[key] for key in PROXY_VARIABLES if key in os.environ})
    return env


def run(command, env):
    command = [str(part) for part in command]
    log("$ " + " ".join(command))
    subprocess.run(command, env=env, check=True)


def capture(command, env):
    return subprocess.run([str(part) for part in command], env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def source_identity():
    try:
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "build-support/python-runtime"],
                               check=True, capture_output=True, text=True).stdout.strip() != ""
        return commit, dirty
    except (OSError, subprocess.CalledProcessError):
        return "unknown", True


def load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if config.get("schemaVersion") != 1:
        raise SystemExit(f"Unsupported python runtime config: {path}")
    names = [layer["name"] for layer in config["layers"]]
    if len(names) != len(set(names)) or not set(config["defaultLayers"]) <= set(names):
        raise SystemExit("Layer names must be unique and defaultLayers must name existing layers")
    return config


def select_layers(config, names):
    wanted = names.split(",") if names else config["defaultLayers"]
    known = {layer["name"]: layer for layer in config["layers"]}
    unknown = [name for name in wanted if name not in known]
    if unknown:
        raise SystemExit(f"Unknown layers: {', '.join(unknown)}")
    return [known[name] for name in wanted]


def platform_tags(arch, glibc):
    """manylinux tags a target with this glibc accepts, newest first."""
    major, minor = (int(part) for part in glibc.split("."))
    if major != 2 or minor < 17:
        raise SystemExit(f"Unsupported target glibc: {glibc}")
    first = 17 if arch == "aarch64" else 5
    tags = [f"manylinux_2_{number}_{arch}" for number in range(minor, first - 1, -1)]
    legacy = {"aarch64": [(17, "manylinux2014")],
              "x86_64": [(17, "manylinux2014"), (12, "manylinux2010"), (5, "manylinux1")]}
    return tags + [f"{name}_{arch}" for floor, name in legacy[arch] if minor >= floor]


def fetch_python(config, arch, downloads, local_archive=None):
    archive = config["python"]["archives"].get(arch)
    if not archive:
        raise SystemExit(f"No interpreter archive configured for {arch}")
    target = downloads / archive["file"]
    if local_archive:
        shutil.copy2(local_archive, target)
    else:
        url = config["python"]["urlTemplate"].format(release=config["python"]["release"],
                                                     file=urllib.parse.quote(archive["file"]))
        log(f"download {url}")
        download(url, target, 120, "Pass a local copy of that archive with --python-archive "
                 "(MASSDB_PYTHON_ARCHIVE for build-for-release.sh); its sha256 is still checked.")
    if digest(target) != archive["sha256"]:
        target.unlink()
        raise SystemExit(f"Interpreter archive checksum mismatch: {archive['file']}")
    return target


def extract_python(archive, env_dir):
    """Unpack the install_only tree (top-level python/) as env_dir."""
    if not hasattr(tarfile, "data_filter"):
        raise SystemExit("This Python lacks tarfile extraction filters; use 3.9.17+, 3.10.12+, 3.11.4+ or 3.12+")
    scratch = Path(tempfile.mkdtemp(prefix=".extract-", dir=env_dir.parent))
    try:
        with tarfile.open(archive) as tar:
            if any(member.name != "python" and not member.name.startswith("python/") for member in tar):
                raise SystemExit("Unexpected interpreter archive layout (expected a top-level python/)")
            tar.extractall(scratch, filter="data")
        (scratch / "python").rename(env_dir)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def python_version(python, env):
    return capture([python, "-I", "-B", "-c", "import platform; print(platform.python_version())"], env)


def installed_distributions(site):
    parser = email.parser.HeaderParser()
    result = {}
    for info in sorted(site.glob("*.dist-info")):
        metadata = parser.parsestr((info / "METADATA").read_text(encoding="utf-8", errors="replace"))
        result[canonical(metadata["Name"])] = {"version": metadata["Version"], "info": info}
    return result


def wheel_entries(wheelhouse, built):
    if any(path.suffix != ".whl" for path in wheelhouse.iterdir()):
        raise SystemExit("The wheelhouse may only contain wheels")
    entries = {}
    for path in sorted(wheelhouse.glob("*.whl")):
        name, version = path.name[:-4].split("-")[:2]
        key = canonical(name)
        if key in entries:
            raise SystemExit(f"More than one wheel resolved for {key}")
        entries[key] = {"name": key, "version": version, "file": path.name, "sha256": digest(path),
                        "origin": "built-from-sdist" if path.name in built else "index"}
    return [entries[key] for key in sorted(entries)]


def fetch_license_texts(config, names, target):
    """Upstream license files for distributions whose wheels ship none, pinned by sha256."""
    fetched = {}
    for name, entries in sorted(config.get("licenseTexts", {}).items()):
        if name not in names:
            continue
        for entry in entries:
            path = target / name / entry["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            log(f"download {entry['url']}")
            download(entry["url"], path, 60, "Check the network or proxy settings of the build host.")
            if digest(path) != entry["sha256"]:
                raise SystemExit(f"License text checksum mismatch: {entry['url']}")
            fetched.setdefault(name, []).append({"file": entry["file"], "url": entry["url"], "sha256": entry["sha256"]})
    return fetched


def parse_lock(path):
    """Header facts and {name: (version, sha256)} of a lock written by resolve."""
    text = Path(path).read_text(encoding="utf-8")
    header = LOCK_HEADER.search(text)
    if not header:
        raise SystemExit(f"Not a lock written by build-python-runtime.py resolve: {path}")
    meta = {"python": header[1], "arch": header[2], "glibc": header[3],
            "layers": [layer.strip() for layer in header[4].split(",")]}
    return meta, {canonical(name): (version, sha256) for name, version, sha256 in LOCK_ENTRY.findall(text)}


def resolve(args):
    config = load_config(args.config)
    arch = host_arch()
    if args.arch and ARCHES.get(args.arch, args.arch) != arch:
        raise SystemExit("Resolve on a host of the target architecture: the target interpreter evaluates markers")
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Use a new or empty resolve directory: {out}")
    downloads, wheelhouse, work = out / "downloads", out / "wheelhouse", out / ".resolver"
    for directory in (downloads, wheelhouse, work / "home"):
        directory.mkdir(parents=True, exist_ok=True)
    archive = fetch_python(config, arch, downloads, args.python_archive)
    extract_python(archive, work / "python")
    python = work / "python" / "bin" / "python"
    env = clean_env(work / "home")
    version = python_version(python, env)
    if version != config["python"]["version"]:
        raise SystemExit(f"Interpreter reports {version}, config pins {config['python']['version']}")

    pins = None
    if args.lock:
        if args.layers or args.target_glibc:
            raise SystemExit("--layers and --target-glibc come from the lock when --lock is given")
        meta, pins = parse_lock(args.lock)
        if (meta["python"], meta["arch"]) != (version, arch):
            raise SystemExit(f"The lock is for Python {meta['python']} {meta['arch']}, not {version} {arch}")
        layers, glibc = select_layers(config, ",".join(meta["layers"])), meta["glibc"]
    else:
        layers = select_layers(config, args.layers)
        glibc = args.target_glibc or config["target"]["glibc"]
    requirements = [spec for layer in layers for spec in layer["requirements"]]
    index_url = args.index_url or config["indexUrl"]
    tags = platform_tags(arch, glibc)
    (out / "requirements.in").write_text(
        "# Generated by build-python-runtime.py resolve from python-runtime.json\n"
        f"# layers: {', '.join(layer['name'] for layer in layers)}\n" + "\n".join(requirements) + "\n",
        encoding="utf-8")
    pip = [python, "-I", "-m", "pip", "--disable-pip-version-check", "--cache-dir", work / "pip-cache"]
    selected = set(pins) if pins is not None else {requirement_name(spec) for spec in requirements}
    built = []
    for spec in config.get("pureSdists", []):
        name = requirement_name(spec)
        if name not in selected:
            continue
        if "==" not in spec:
            raise SystemExit(f"A pure-Python sdist must be pinned exactly: {spec}")
        if pins is not None and pins[name][0] != spec.split("==", 1)[1]:
            raise SystemExit(f"The lock pins {name} {pins[name][0]}, pureSdists says {spec}")
        before = set(wheelhouse.iterdir())
        # A fixed SOURCE_DATE_EPOCH (1980-01-01, the zip minimum) makes the built wheel byte-reproducible.
        run(pip + ["wheel", "--no-deps", "--no-binary", name, "--wheel-dir", wheelhouse,
                   "--index-url", index_url, spec], dict(env, SOURCE_DATE_EPOCH="315532800"))
        new = sorted(set(wheelhouse.iterdir()) - before)
        if len(new) != 1 or not new[0].name.endswith("-none-any.whl"):
            raise SystemExit(f"{spec} did not build exactly one pure-Python wheel: {[path.name for path in new]}")
        built.append(new[0].name)
    command = pip + ["download", "--dest", wheelhouse, "--find-links", wheelhouse, "--only-binary=:all:",
                     "--implementation", "cp", "--python-version", ".".join(version.split(".")[:2]),
                     "--index-url", index_url]
    for tag in tags:
        command += ["--platform", tag]
    # With a lock, download exactly its files; pure-sdist wheels built above are found via --find-links.
    run(command + (["--no-deps", "--require-hashes", "-r", args.lock] if pins is not None
                   else ["-r", out / "requirements.in"]), env)

    wheels = wheel_entries(wheelhouse, built)
    texts = fetch_license_texts(config, {wheel["name"] for wheel in wheels}, out / "license-texts")
    lock = out / "requirements.lock"
    if pins is not None:
        fetched = {wheel["name"]: (wheel["version"], wheel["sha256"]) for wheel in wheels}
        if fetched != pins:
            raise SystemExit("Fetched wheels differ from the lock: " + ", ".join(
                sorted(name for name in set(fetched) | set(pins) if fetched.get(name) != pins.get(name))))
        shutil.copyfile(args.lock, lock)
    else:
        lock.write_text(
            "# MassDB SQL Python runtime lock, generated by build-python-runtime.py resolve\n"
            f"# python {version} {arch}; target glibc {glibc}; layers {', '.join(layer['name'] for layer in layers)}\n"
            + "".join(f"{wheel['name']}=={wheel['version']} \\\n    --hash=sha256:{wheel['sha256']}\n"
                      for wheel in wheels), encoding="utf-8")
    commit, dirty = source_identity()
    shutil.copy2(args.config, out / "python-runtime.json")
    record = {
        "schemaVersion": 1,
        "python": {"version": version, "archive": archive.name, "sha256": digest(archive)},
        "arch": arch,
        "targetGlibc": glibc,
        "platformTags": tags,
        "layers": [layer["name"] for layer in layers],
        "indexUrl": index_url,
        "pip": capture(pip + ["--version"], env).split()[1],
        "resolvedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceCommit": commit,
        "sourceModified": dirty,
        "lockSha256": digest(lock),
        "lockSource": "committed" if pins is not None else "resolved",
        "wheels": wheels,
        "licenseTexts": texts,
    }
    (out / "resolve.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(work)
    log(f"resolved {len(wheels)} wheels for Python {version} {arch} into {out}")


def verify_inputs(inputs, record):
    archive = inputs / "downloads" / record["python"]["archive"]
    if digest(archive) != record["python"]["sha256"]:
        raise SystemExit(f"Interpreter archive changed since resolve: {archive}")
    lock = inputs / "requirements.lock"
    if digest(lock) != record["lockSha256"]:
        raise SystemExit("requirements.lock changed since resolve")
    wheelhouse = inputs / "wheelhouse"
    expected = {wheel["file"]: wheel["sha256"] for wheel in record["wheels"]}
    actual = {path.name for path in wheelhouse.iterdir()}
    if actual != set(expected):
        raise SystemExit(f"Wheelhouse differs from resolve.json: {sorted(actual ^ set(expected))}")
    for name, sha256 in expected.items():
        if digest(wheelhouse / name) != sha256:
            raise SystemExit(f"Wheel changed since resolve: {name}")
    for name, entries in record.get("licenseTexts", {}).items():
        for entry in entries:
            if digest(inputs / "license-texts" / name / entry["file"]) != entry["sha256"]:
                raise SystemExit(f"License text changed since resolve: {name}/{entry['file']}")
    return archive, lock, wheelhouse


def rewrite_scripts(env_dir, interpreter):
    """Replace pip's absolute build-path launchers with the relocatable one.

    pip writes ``#!<env>/bin/python`` or, when that is longer than the kernel shebang limit, a
    ``/bin/sh`` launcher that execs the absolute interpreter path.
    """
    location = re.escape(str(env_dir).encode())
    header = re.compile(rb"\A(?:#!" + location + rb"/\S+\n|#!/bin/sh\n'''exec' \"?" + location
                        + rb"/[^\s\"]+\"? \"\$0\" \"\$@\"\n' '''\n)")
    rewritten = set()
    for path in sorted((env_dir / "bin").iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        match = header.match(data)
        if match:
            path.write_bytes(TRAMPOLINE.format(python=interpreter).encode() + data[match.end():])
            rewritten.add(path.resolve())
    return rewritten


def update_records(site, changed):
    """Refresh RECORD hashes and sizes of files rewritten after pip installed them."""
    for record in sorted(site.glob("*.dist-info/RECORD")):
        with open(record, newline="", encoding="utf-8") as stream:
            text = stream.read()
        rows = list(csv.reader(text.splitlines()))
        touched = False
        for row in rows:
            path = (site / row[0]).resolve() if row else None
            if path in changed:
                data = path.read_bytes()
                row[1] = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                row[2] = str(len(data))
                touched = True
        if touched:
            with open(record, "w", newline="", encoding="utf-8") as stream:
                csv.writer(stream, lineterminator="\r\n" if "\r\n" in text else "\n").writerows(rows)


def collect_licenses(root, env_dir, site, version, major_minor, supplements):
    supplements, supplements_for = supplements
    target = root / "LICENSES"
    cpython = target / f"cpython-{version}"
    cpython.mkdir(parents=True)
    shutil.copy2(env_dir / "lib" / f"python{major_minor}" / "LICENSE.txt", cpython / "LICENSE.txt")
    for name, item in installed_distributions(site).items():
        info = item["info"]
        files = [(path, path.relative_to(info / "licenses")) for path in (info / "licenses").rglob("*")
                 if path.is_file()] if (info / "licenses").is_dir() else []
        files += [(path, Path(path.name)) for path in info.iterdir()
                  if path.is_file() and LICENSE_FILE.match(path.name)]
        files += [(supplements / name / entry["file"], Path(entry["file"]))
                  for entry in supplements_for.get(name, [])]
        for source, relative in files:
            destination = target / f"{name}-{item['version']}" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def find_leaks(root, marker):
    """Files that still mention the build directory (the runtime must not depend on it)."""
    leaks = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            continue
        with open(path, "rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if data.find(marker) >= 0:
                leaks.append(path.relative_to(root).as_posix())
    return leaks


def pack(root, tarball, epoch):
    """Deterministic tar.gz of root: sorted entries, root ownership, fixed mtimes."""
    def add(tar, path):
        info = tar.gettarinfo(str(path), arcname=path.relative_to(root.parent).as_posix())
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = epoch
        if info.isreg():
            with open(path, "rb") as stream:
                tar.addfile(info, stream)
        else:
            tar.addfile(info)

    with open(tarball, "wb") as raw, \
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as packed, \
            tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as tar:
        add(tar, root)
        for directory, names, files in os.walk(root):
            names.sort()
            for name in sorted(names + files):
                add(tar, Path(directory) / name)
    (tarball.parent / (tarball.name + ".sha256")).write_text(f"{digest(tarball)}  {tarball.name}\n", encoding="utf-8")


def build(args):
    inputs = args.inputs.resolve()
    record = json.loads((inputs / "resolve.json").read_text(encoding="utf-8"))
    config = load_config(inputs / "python-runtime.json")
    arch = host_arch()
    if record["arch"] != arch:
        raise SystemExit(f"Build on a {record['arch']} host: installation byte-compiles with the target interpreter")
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Use a new or empty build directory: {out}")
    archive, lock, wheelhouse = verify_inputs(inputs, record)

    version = record["python"]["version"]
    major_minor = ".".join(version.split(".")[:2])
    env_name = config["layout"]["envName"].format(version=version)
    root = out / "stage" / config["layout"]["rootName"]
    (root / "envs").mkdir(parents=True)
    env_dir = root / "envs" / env_name
    extract_python(archive, env_dir)
    python = env_dir / "bin" / "python"
    home = out / ".home"
    home.mkdir()
    env = clean_env(home)
    if python_version(python, env) != version:
        raise SystemExit("Extracted interpreter version differs from resolve.json")
    preinstalled = installed_distributions(env_dir / "lib" / f"python{major_minor}" / "site-packages")

    # --no-index: nothing but the archived wheelhouse. -B and --no-compile: no bytecode with build paths;
    # compileall -f below rewrites every .pyc as checked-hash with paths relative to the runtime root.
    run([python, "-I", "-B", "-m", "pip", "install", "--no-index", "--find-links", wheelhouse, "--require-hashes",
         "--only-binary=:all:", "--no-compile", "--no-cache-dir", "--no-warn-script-location",
         "--disable-pip-version-check", "-r", lock], env)
    site = env_dir / "lib" / f"python{major_minor}" / "site-packages"
    update_records(site, rewrite_scripts(env_dir, f"python{major_minor}"))
    installed = installed_distributions(site)
    expected = {wheel["name"]: wheel["version"] for wheel in record["wheels"]}
    expected.update({name: item["version"] for name, item in preinstalled.items()})
    if {name: item["version"] for name, item in installed.items()} != expected:
        raise SystemExit("Installed distributions differ from the lock plus the interpreter's own packages")
    # One process in sorted order: parallel workers make marshal output depend on scheduling.
    compiled = subprocess.run([str(python), "-I", "-B", "-m", "compileall", "-f", "-q", "-j", "1",
                               "--invalidation-mode", "checked-hash", "-s", str(root),
                               str(env_dir / "lib" / f"python{major_minor}")], env=env, capture_output=True, text=True)
    compile_failures = sorted(set(re.findall(r"\*\*\* Error compiling '([^']+)'", compiled.stdout)))
    if compiled.returncode and not compile_failures:
        raise SystemExit(f"compileall failed:\n{compiled.stdout}{compiled.stderr}")
    for path in compile_failures:
        log(f"warning: not byte-compiled (source kept): {path}")
    shutil.rmtree(home)

    collect_licenses(root, env_dir, site, version, major_minor,
                     (inputs / "license-texts", record.get("licenseTexts", {})))
    shutil.copy2(lock, root / "requirements.lock")
    leaks = find_leaks(root, str(out).encode())
    if leaks:
        raise SystemExit("Build paths leaked into the runtime:\n  " + "\n  ".join(leaks[:50]))

    epoch = int(datetime.strptime(record["resolvedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    commit, dirty = source_identity()
    be_conf = {"enable_python_udf_support": "true", "python_env_mode": "conda",
               "python_conda_root_path": config["layout"]["beConfRoot"], "PYTHONNOUSERSITE": "1"}
    packages = [dict(wheel) for wheel in record["wheels"]]
    packages += [{"name": name, "version": item["version"], "origin": "interpreter"}
                 for name, item in preinstalled.items()]
    manifest = {
        "schemaVersion": 1,
        "component": "massdb-sql-python-runtime",
        "python": {"implementation": "CPython", "version": version,
                   "distribution": config["python"]["distribution"], "release": config["python"]["release"],
                   "archive": archive.name, "archiveSha256": record["python"]["sha256"]},
        "arch": arch,
        "env": {"name": env_name, "executable": f"envs/{env_name}/bin/python",
                "sitePackages": f"envs/{env_name}/lib/python{major_minor}/site-packages"},
        "target": {"glibc": record["targetGlibc"], "glibcxx": config["target"].get("glibcxx"),
                   "cxxabi": config["target"].get("cxxabi"), "minLoadAlign": config["target"]["minLoadAlign"],
                   "platformTags": record["platformTags"]},
        "layers": record["layers"],
        "lockSha256": record["lockSha256"],
        "packages": sorted(packages, key=lambda package: package["name"]),
        "notByteCompiled": [Path(path).relative_to(root).as_posix() for path in compile_failures],
        "beConf": be_conf,
        "runtimeVersion": version,
        "sourceCommit": commit,
        "sourceModified": dirty,
        "sourceDateEpoch": epoch,
        "buildHost": {"arch": arch, "pageSize": os.sysconf("SC_PAGE_SIZE"), "glibc": platform.libc_ver()[1]},
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "README.txt").write_text(
        f"MassDB SQL Python 运行时 {version}（{arch}）\n\n"
        "安装：在每台 BE 上解压到 BE 的 lib 目录，得到 lib/python-runtime/"
        f"envs/{env_name}/bin/python：\n"
        "  tar -xzf <本运行时包> -C <BE 安装目录>/lib\n\n"
        "be.conf（改完重启 BE）：\n" + "".join(f"  {key} = {value}\n" for key, value in be_conf.items()) + "\n"
        f"重启后执行 SHOW PYTHON VERSIONS; 应能看到 {version}；建函数时写 \"runtime_version\" = \"{version}\"（完整版本号）。\n"
        "envs/ 下只能放完整可用的环境，否则 BE 启动失败；升级 Python 补丁版本时新旧环境需并存到函数迁移完。\n"
        f"目标系统：glibc ≥ {record['targetGlibc']}；BE 静态链接了 libstdc++，本运行时则使用系统的 libstdc++"
        f"（GLIBCXX_{config['target'].get('glibcxx') or '?'}、CXXABI_{config['target'].get('cxxabi') or '?'} 及以上）、"
        "libgcc_s 和 libz.so.1" + ("；lightgbm 还需要 libgomp.so.1（含 GOMP_4.5）" if "lightgbm" in installed else "")
        + "。\n"
        "组件和版本见 MANIFEST.json，许可证正文见 LICENSES/。\n", encoding="utf-8")

    tarball = out / f"massdb-python-runtime-{version}-{arch}-{record['lockSha256'][:8]}.tar.gz"
    log(f"packing {tarball.name}")
    pack(root, tarball, epoch)
    log(f"built {tarball} ({tarball.stat().st_size / 1048576:.1f} MiB); next: check-python-runtime.py {tarball}")


def release(args):
    """Fetch (or reuse), build, check and unpack the runtime into a BE component directory."""
    lock, be_dir, work = args.lock.resolve(), args.be_dir.resolve(), args.work.resolve()
    if not lock.is_file():
        raise SystemExit(f"No committed lock for this architecture: {lock}. Run resolve on such a host and "
                         "commit its requirements.lock there, or build the release without the Python runtime.")
    server = be_dir / "plugins" / "python_udf" / "python_server.py"
    if not (be_dir / "lib").is_dir() or not server.is_file():
        raise SystemExit(f"Not a built BE component (lib/ and plugins/python_udf/python_server.py): {be_dir}")
    target = be_dir / "lib" / load_config(args.config)["layout"]["rootName"]
    if target.exists():
        raise SystemExit(f"Refusing to replace an existing runtime: {target}")
    if work.exists() and any(work.iterdir()):
        raise SystemExit(f"Use a new or empty work directory: {work}")
    if args.inputs:
        inputs = args.inputs.resolve()
        if (inputs / "requirements.lock").read_bytes() != lock.read_bytes():
            raise SystemExit(f"{inputs} was not fetched from {lock}")
    else:
        inputs = work / "inputs"
        resolve(argparse.Namespace(config=args.config, output=inputs, layers=None, index_url=args.index_url,
                                   target_glibc=None, python_archive=args.python_archive, arch=None, lock=lock))
    build(argparse.Namespace(inputs=inputs, output=work / "build"))
    tarball = next((work / "build").glob("massdb-python-runtime-*.tar.gz"))
    log(f"checking {tarball.name} against {server}")
    subprocess.run([sys.executable, str(HERE / "check-python-runtime.py"), str(tarball), "--config", str(args.config),
                    "--server-script", str(server), "--report", str(work / "check.json")], check=True)
    with tarfile.open(tarball) as tar:
        tar.extractall(be_dir / "lib", filter="data")
    if not (target / "MANIFEST.json").is_file():
        raise SystemExit(f"{tarball.name} did not unpack to {target}")
    log(f"installed {tarball.name} as {target}; inputs for an offline rebuild: {inputs}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    online = commands.add_parser("resolve", help="fetch the interpreter and wheels, write requirements.lock")
    online.add_argument("--config", type=Path, default=HERE / "python-runtime.json")
    online.add_argument("--output", type=Path, required=True, help="new resolve directory (keep it as build input)")
    online.add_argument("--layers", help="comma-separated layer names (default: defaultLayers)")
    online.add_argument("--index-url", help="PyPI-compatible index or mirror (default: config indexUrl)")
    online.add_argument("--target-glibc", help="oldest glibc on target BEs, e.g. 2.28 (default: config)")
    online.add_argument("--python-archive", type=Path, help="use this local interpreter archive instead of downloading")
    online.add_argument("--arch", help="target architecture; must equal the build host")
    online.add_argument("--lock", type=Path, help="fetch exactly this committed lock instead of resolving the layers")
    offline = commands.add_parser("build", help="install the lock offline and pack the runtime tarball")
    offline.add_argument("--inputs", type=Path, required=True, help="directory written by resolve")
    offline.add_argument("--output", type=Path, required=True, help="new build directory")
    packaging = commands.add_parser("release", help="fetch from the committed lock, build, check, unpack into a BE")
    packaging.add_argument("--config", type=Path, default=HERE / "python-runtime.json")
    packaging.add_argument("--lock", type=Path,
                           default=HERE / "locks" / f"requirements-{platform.machine().lower()}.lock",
                           help="committed lock (default: locks/requirements-<host arch>.lock)")
    packaging.add_argument("--be-dir", type=Path, required=True, help="built BE component (output of build.sh)")
    packaging.add_argument("--work", type=Path, required=True, help="new work directory")
    packaging.add_argument("--inputs", type=Path, help="archived resolve directory of the same lock (offline build)")
    packaging.add_argument("--index-url", help="PyPI-compatible index or mirror (default: config indexUrl)")
    packaging.add_argument("--python-archive", type=Path,
                           help="local copy of the configured interpreter archive (sha256 is checked)")
    args = parser.parse_args()
    try:
        {"resolve": resolve, "build": build, "release": release}[args.command](args)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Command failed with exit code {error.returncode}: {' '.join(error.cmd)}")


if __name__ == "__main__":
    main()
