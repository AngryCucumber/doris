#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""HASI benchmark dataset generator (design doc HASI_POC.md §8.3, "synthetic-skewed").

Emits CSV rows `id,lon,lat`: 70% of points in gaussian city clusters (sigma ~5 km),
30% uniform on the sphere. Deterministic for a fixed seed so runs are comparable.

  python3 gen_synthetic.py <rows> [seed] > data.csv
"""

import math
import random
import sys


def main():
    rows = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20260715
    rng = random.Random(seed)

    # 20 "cities", first few pinned so bench queries can target known-dense centers.
    cities = [
        (116.40, 39.90),   # beijing (primary bench target)
        (121.47, 31.23),   # shanghai
        (-74.00, 40.71),   # new york
        (2.35, 48.86),     # paris
        (151.21, -33.87),  # sydney
        (179.95, 10.0),    # antimeridian cluster (edge-case coverage)
    ]
    while len(cities) < 20:
        lon = rng.uniform(-180.0, 180.0)
        lat = math.degrees(math.asin(rng.uniform(-0.95, 0.95)))
        cities.append((lon, lat))

    sigma_deg = 5.0 / 111.0  # ~5 km in latitude degrees
    out = sys.stdout
    for i in range(rows):
        if rng.random() < 0.7:
            clon, clat = cities[rng.randrange(len(cities))]
            lat = clat + rng.gauss(0.0, sigma_deg)
            lat = max(-89.9, min(89.9, lat))
            lon = clon + rng.gauss(0.0, sigma_deg) / max(0.2, math.cos(math.radians(clat)))
            if lon > 180.0:
                lon -= 360.0
            if lon < -180.0:
                lon += 360.0
        else:
            lon = rng.uniform(-180.0, 180.0)
            lat = math.degrees(math.asin(rng.uniform(-1.0, 1.0)))
        out.write(f"{i},{lon:.7f},{lat:.7f}\n")


if __name__ == "__main__":
    main()
