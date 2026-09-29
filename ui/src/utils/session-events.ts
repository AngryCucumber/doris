// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
export const SESSION_EVENT = 'massdb-session-changed';
export const SESSION_CHANNEL = 'massdb-session';

/** Clear transient sensitive forms immediately, including same-user sign-ins in another tab. */
export function announceSessionChange(): void {
    window.dispatchEvent(new Event(SESSION_EVENT));
    if (typeof BroadcastChannel !== 'undefined') {
        const channel = new BroadcastChannel(SESSION_CHANNEL);
        channel.postMessage('changed');
        channel.close();
    }
}
