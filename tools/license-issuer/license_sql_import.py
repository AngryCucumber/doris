#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Write a bounded compact certificate as text SQL for a MySQL client's standard input."""

import argparse
import pathlib
import re
import sys


MAX_BYTES = 64 * 1024
PREFIXES = {
    "import": "ADMIN IMPORT LICENSE",
    "validate": "ADMIN VALIDATE LICENSE",
    "clock-repair": "ADMIN REPAIR LICENSE CLOCK",
}


def make_sql(certificate, operation="import"):
    """A compact JWS alphabet contains no SQL quotes or escapes, in either SQL escape mode."""
    if operation not in PREFIXES:
        raise ValueError("Unsupported operation")
    if len(certificate) > MAX_BYTES:
        raise ValueError("Certificate exceeds 64 KiB")
    if not re.fullmatch(rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", certificate):
        raise ValueError("Expected exact compact JWS bytes without whitespace")
    return PREFIXES[operation] + " '" + certificate.decode("ascii") + "';\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=pathlib.Path)
    parser.add_argument("--operation", choices=tuple(PREFIXES), default="import")
    args = parser.parse_args()
    try:
        with args.certificate.open("rb") as stream:
            certificate = stream.read(MAX_BYTES + 1)
        sql = make_sql(certificate, args.operation)
    except (OSError, ValueError):
        # Do not include paths, certificate bytes or an underlying parser exception in diagnostics.
        parser.exit(2, "Cannot read a compact certificate of at most 64 KiB\n")
    sys.stdout.write(sql)


if __name__ == "__main__":
    main()
