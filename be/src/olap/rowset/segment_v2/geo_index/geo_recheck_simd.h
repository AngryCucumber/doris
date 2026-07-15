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

#include <s2/s1angle.h>
#include <s2/s2cap.h>
#include <s2/s2latlng.h>
#include <s2/s2latlng_rect.h>

#include <cmath>
#include <cstddef>
#include <cstdint>

#include "geo/geo_common.h"
#include "geo/geo_types.h"

namespace doris::segment_v2 {

// Three-band exact-recheck kernel for circle predicates (design doc §4.6, contract C2):
//   band 1  clear-accept:  inside a conservative inner lat/lng box of the shrunk cap
//   band 2  clear-reject:  outside the rect bound of the expanded cap
//   band 3  margin:        delegate to the *same* scalar code the full-scan path runs,
//                          so the index path is bit-identical to a table scan.
// The kernel never re-implements a distance formula for the final verdict; the margin
// absorbs haversine-vs-chord differences and float error (haversine keeps only ~8
// significant digits at earth scale, so the margin is an absolute meters value).
//
// This is v0 unit-test-level code: the loop is a scalar auto-vectorizable prefilter;
// explicit SIMD can replace it later without changing the contract.

enum class GeoCirclePredicate {
    DISTANCE_LT,     // ST_Distance_Sphere(lng, lat, lng0, lat0) <  r   (open, haversine)
    DISTANCE_LE,     // ST_Distance_Sphere(lng, lat, lng0, lat0) <= r   (closed, haversine)
    CONTAINS_CIRCLE, // ST_Contains(ST_Circle(lng0, lat0, r), ST_Point(lng, lat))
                     //   = S2Cap::Contains, closed chord-angle comparison
};

struct GeoRecheckStats {
    size_t fast_accept = 0;
    size_t fast_reject = 0;
    size_t exact_calls = 0;
};

class CircleRecheck {
public:
    // Same numeric domain as the scalar functions: 6371010 m sphere (S2Earth).
    static constexpr double kEarthRadiusMeters = 6371010.0;
    // Absolute margin: well above the ~10 cm error floor of earth-scale haversine and
    // the haversine-vs-chord formula gap near the boundary; negligible for selectivity.
    static constexpr double kMarginMeters = 1.0;

    bool init(double lng0, double lat0, double radius_m, GeoCirclePredicate pred) {
        S2LatLng center = S2LatLng::FromDegrees(lat0, lng0);
        if (!center.is_valid() || !(radius_m > 0)) {
            return false;
        }
        _pred = pred;
        _lng0 = lng0;
        _lat0 = lat0;
        _radius_m = radius_m;
        if (pred == GeoCirclePredicate::CONTAINS_CIRCLE &&
            _circle.init(lng0, lat0, radius_m) != GEO_PARSE_OK) {
            return false;
        }

        const double theta = radius_m / kEarthRadiusMeters;
        const double dtheta = kMarginMeters / kEarthRadiusMeters;

        // Band 2: rect bound of the cap expanded by the margin. Outside it, every
        // predicate form is definitely false. GetRectBound natively handles poles and
        // the antimeridian; its lng interval is symmetric around the center longitude.
        S2Cap reject_cap(center.ToPoint(), S1Angle::Radians(theta + dtheta));
        S2LatLngRect rect = reject_cap.GetRectBound();
        _rect_lat_lo_deg = rect.lat_lo().degrees();
        _rect_lat_hi_deg = rect.lat_hi().degrees();
        _lng_full = rect.lng().is_full();
        _rect_lng_half_deg = _lng_full ? 180.0 : S1Angle::Radians(rect.lng().GetLength()).degrees() / 2.0;

        // Band 1: inner lat/lng box fully inside the cap shrunk by the margin.
        // For any point (lat0+u, lng0+v) with |u| <= U, |v| <= V the haversine angle
        // satisfies  a <= sin^2(U/2) + cos(lat0) * cmax * sin^2(V/2)  where cmax bounds
        // cos(lat0+u) over the box (NOT a corners-only argument, which would be unsafe).
        _has_inner = false;
        const double theta_acc = theta - dtheta;
        const double lat0_abs_deg = std::fabs(lat0);
        const double theta_deg = theta * 180.0 / M_PI;
        if (theta_acc > 0 && lat0_abs_deg + theta_deg < 89.9) {
            const double u = theta_acc / std::sqrt(2.0); // radians
            const double lat0_rad = lat0 * M_PI / 180.0;
            const double cmax = (std::fabs(lat0_rad) <= u)
                                        ? 1.0
                                        : std::cos(std::fabs(lat0_rad) - u);
            const double su = std::sin(u / 2);
            const double st = std::sin(theta_acc / 2);
            const double num = st * st - su * su;
            const double den = std::cos(lat0_rad) * cmax;
            if (num > 0 && den > 0) {
                const double sv = std::sqrt(num / den);
                if (sv < 1.0) {
                    const double v = 2 * std::asin(sv); // radians
                    _inner_dlat_deg = u * 180.0 / M_PI;
                    _inner_dlng_deg = v * 180.0 / M_PI;
                    _has_inner = _inner_dlng_deg > 0;
                }
            }
        }
        return true;
    }

    // keep[i] = 1 iff row i satisfies the original predicate, bit-identical to the
    // full-scan path (invalid coordinates evaluate to NULL there, i.e. filtered: 0).
    // Caller handles column NULLs.
    void recheck(const double* lng, const double* lat, size_t n, uint8_t* keep,
                 GeoRecheckStats* stats = nullptr) const {
        for (size_t i = 0; i < n; ++i) {
            const double la = lat[i];
            const double lo = lng[i];
            // Band 2: outside the expanded rect bound -> definite reject.
            if (la < _rect_lat_lo_deg || la > _rect_lat_hi_deg) {
                keep[i] = 0;
                if (stats != nullptr) ++stats->fast_reject;
                continue;
            }
            double d = 0;
            if (!_lng_full) {
                d = lo - _lng0;
                d -= 360.0 * std::round(d / 360.0);
                if (std::fabs(d) > _rect_lng_half_deg) {
                    keep[i] = 0;
                    if (stats != nullptr) ++stats->fast_reject;
                    continue;
                }
            } else {
                d = lo - _lng0;
                d -= 360.0 * std::round(d / 360.0);
            }
            // Band 1: inside the inner box -> definite accept. Coordinate validity must
            // be checked first: the scalar path returns NULL (filtered) for |lng| > 180,
            // and a fast-accept would resurrect such rows.
            if (_has_inner && std::fabs(lo) <= 180.0 && std::fabs(la) <= 90.0 &&
                std::fabs(la - _lat0) <= _inner_dlat_deg && std::fabs(d) <= _inner_dlng_deg) {
                keep[i] = 1;
                if (stats != nullptr) ++stats->fast_accept;
                continue;
            }
            // Band 3: margin -> the exact same code the table scan runs.
            keep[i] = exact(lo, la) ? 1 : 0;
            if (stats != nullptr) ++stats->exact_calls;
        }
    }

private:
    bool exact(double lng, double lat) const {
        switch (_pred) {
        case GeoCirclePredicate::DISTANCE_LT:
        case GeoCirclePredicate::DISTANCE_LE: {
            double dist = 0;
            if (!GeoPoint::ComputeDistance(lng, lat, _lng0, _lat0, &dist)) {
                return false; // scalar path yields NULL -> row filtered
            }
            return _pred == GeoCirclePredicate::DISTANCE_LT ? dist < _radius_m
                                                            : dist <= _radius_m;
        }
        case GeoCirclePredicate::CONTAINS_CIRCLE: {
            GeoPoint point;
            if (point.from_coord(lng, lat) != GEO_PARSE_OK) {
                return false;
            }
            return _circle.contains(&point);
        }
        }
        return false;
    }

    GeoCirclePredicate _pred = GeoCirclePredicate::DISTANCE_LT;
    double _lng0 = 0;
    double _lat0 = 0;
    double _radius_m = 0;
    GeoCircle _circle;

    double _rect_lat_lo_deg = 0;
    double _rect_lat_hi_deg = 0;
    double _rect_lng_half_deg = 0;
    bool _lng_full = false;

    bool _has_inner = false;
    double _inner_dlat_deg = 0;
    double _inner_dlng_deg = 0;
};

} // namespace doris::segment_v2
