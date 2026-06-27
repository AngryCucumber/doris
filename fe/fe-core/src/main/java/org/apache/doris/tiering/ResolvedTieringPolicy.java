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

package org.apache.doris.tiering;

/**
 * Effective tiering policy for one tablet after field-level merge of the
 * table/partition scopes over the config defaults (design v2 §6.1). All fields
 * are concrete (no nulls): unset scope fields fell back to the parent/default.
 */
public class ResolvedTieringPolicy {
    public boolean enabled;
    public double hotThreshold;
    public double coldThreshold;
    public long cooldownTimeSec;
    public long minHotResidenceSec;
    public long minColdResidenceSec;
    public long maxSsdBytes;
    public double pointLookupWeight;
    public double scanBytesWeight;
    public double batchScanPenalty;
    public boolean manualHold;
    public long effectiveRevision;
}
