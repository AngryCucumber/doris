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
#include <cstring>
#include <string>

namespace doris::segment_v2::hasi_fmt {

// HASI on-disk format primitives, shared by the builder/parser (hasi_tree.cpp)
// and the compaction splice path (hasi_splice.cpp). Layout: HASI_POC.md §4.2/§12.

constexpr uint32_t kMagic = 0x48415349; // "HASI"
constexpr uint32_t kVersionV1 = 1;
constexpr uint32_t kVersionV2 = 2; // adds the trailing measures section
constexpr size_t kHeaderSize = 24;
constexpr size_t kDirEntrySize = 36;
constexpr size_t kLeafMeasureSize = 28; // f64 sum, f64 min, f64 max, u32 non_null

inline void put_u32(std::string* out, uint32_t v) {
    char buf[4];
    std::memcpy(buf, &v, 4);
    out->append(buf, 4);
}

inline void put_u64(std::string* out, uint64_t v) {
    char buf[8];
    std::memcpy(buf, &v, 8);
    out->append(buf, 8);
}

inline uint32_t get_u32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline uint64_t get_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

inline void put_varint(std::string* out, uint64_t v) {
    while (v >= 0x80) {
        out->push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out->push_back(static_cast<char>(v));
}

// Returns bytes consumed, 0 on malformed/overlong input.
inline size_t get_varint(const uint8_t* p, const uint8_t* end, uint64_t* v) {
    uint64_t result = 0;
    int shift = 0;
    const uint8_t* cur = p;
    while (cur < end && shift < 64) {
        uint8_t byte = *cur++;
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            *v = result;
            return cur - p;
        }
        shift += 7;
    }
    return 0;
}

inline uint64_t zigzag_encode(int64_t v) {
    return (static_cast<uint64_t>(v) << 1) ^ static_cast<uint64_t>(v >> 63);
}

inline int64_t zigzag_decode(uint64_t v) {
    return static_cast<int64_t>(v >> 1) ^ -static_cast<int64_t>(v & 1);
}

} // namespace doris::segment_v2::hasi_fmt
