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

#pragma once

#include <cstdint>
#include <string>

namespace doris {

// Text codec for the GEO_POINT scalar type (HASI_POC.md §10): the stored value is
// the flipped s2 leaf cell key (raw id XOR 2^63, GeoPoint::ComputeS2CellKey), the
// text form is "[lon, lat]" in GeoJSON axis order — brackets required, bare "a,b"
// is deliberately rejected because the ES bare-string convention is lat,lon and
// silently accepting either axis order would corrupt data. Implementations live in
// the .cpp to keep S2 headers out of olap/types.h (FieldTypeTraits includes this).
class GeoPointValue {
public:
    // Parses "[lon, lat]" (surrounding/internal whitespace tolerated). Returns false
    // on malformed text or out-of-range coordinates (|lon| > 180, |lat| > 90).
    static bool from_string(int64_t* cell_key, const char* s, size_t len);

    static bool from_string(int64_t* cell_key, const std::string& s) {
        return from_string(cell_key, s.data(), s.size());
    }

    // Formats the decoded cell center as "[lon, lat]" with shortest round-trip
    // representations (re-encoding the printed center always lands on the same
    // cell). Keys that do not denote a valid cell (only reachable via a raw BIGINT
    // cast) format as "[invalid]", which from_string rejects back to NULL.
    static std::string to_string(int64_t cell_key);
};

} // namespace doris
