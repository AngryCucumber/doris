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
 * Reason a tablet target medium / tier state changed. Used for audit, SHOW and
 * fault localization. See design v2 §6.3 / §13.
 */
public enum TieringReasonCode {
    NONE,
    HIGH_QPS_PROMOTE,
    LOW_ACCESS_DEMOTE,
    LIFECYCLE_DEMOTE,
    SSD_PRESSURE_EVICT,
    MANUAL_SET,
    POLICY_HOLD,
    REMOTE_COOLDOWN_DATA,
    SSD_CAPACITY_NOT_ENOUGH,
    HDD_CAPACITY_NOT_ENOUGH,
    TARGET_MEDIUM_UNAVAILABLE
}
