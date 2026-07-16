// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "vec/runtime/geo_point_value.h"

#include <fmt/format.h>

#include <cctype>
#include <cstdlib>

#include "geo/geo_types.h"

namespace doris {

namespace {

// Parses one finite double at *pos (skipping leading whitespace), advancing *pos
// past it. strtod also accepts inf/nan/hex — rejected by the isfinite check and by
// the coordinate range check in the caller.
bool parse_double(const char* s, size_t len, size_t* pos, double* out) {
    while (*pos < len && std::isspace(static_cast<unsigned char>(s[*pos]))) {
        ++*pos;
    }
    if (*pos >= len) {
        return false;
    }
    // strtod needs NUL-terminated input; the slice is small, copy is fine.
    std::string buf(s + *pos, len - *pos);
    char* end = nullptr;
    errno = 0;
    double v = std::strtod(buf.c_str(), &end);
    if (end == buf.c_str() || errno == ERANGE || !std::isfinite(v)) {
        return false;
    }
    *pos += static_cast<size_t>(end - buf.c_str());
    *out = v;
    return true;
}

bool expect_char(const char* s, size_t len, size_t* pos, char c) {
    while (*pos < len && std::isspace(static_cast<unsigned char>(s[*pos]))) {
        ++*pos;
    }
    if (*pos >= len || s[*pos] != c) {
        return false;
    }
    ++*pos;
    return true;
}

} // namespace

bool GeoPointValue::from_string(int64_t* cell_key, const char* s, size_t len) {
    size_t pos = 0;
    double lon = 0;
    double lat = 0;
    if (!expect_char(s, len, &pos, '[') || !parse_double(s, len, &pos, &lon) ||
        !expect_char(s, len, &pos, ',') || !parse_double(s, len, &pos, &lat) ||
        !expect_char(s, len, &pos, ']')) {
        return false;
    }
    while (pos < len && std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
    if (pos != len) {
        return false;
    }
    // ComputeS2CellKey validates the S2LatLng range (|lat| <= 90); longitude must be
    // checked here because S2LatLng treats e.g. 360 as valid by normalization, which
    // would silently alias distinct user inputs.
    if (lon < -180.0 || lon > 180.0 || lat < -90.0 || lat > 90.0) {
        return false;
    }
    return GeoPoint::ComputeS2CellKey(lon, lat, cell_key);
}

std::string GeoPointValue::to_string(int64_t cell_key) {
    double lon = 0;
    double lat = 0;
    if (!GeoPoint::DecodeS2CellKey(cell_key, &lon, &lat)) {
        return "[invalid]";
    }
    return fmt::format("[{}, {}]", lon, lat);
}

} // namespace doris
