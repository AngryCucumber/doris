// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
declare const __MASSDB_BRANDING__: {
    productName: string;
    productVersion: string;
    productDisplayVersion: string;
    sourceCommit: string;
    sourceModified: boolean | null;
    companyZh: string;
    companyEn: string;
    copyrightYears: string;
    companyCopyrightConfirmed: boolean;
    upstream: { name: string; sourceVersion: string; sourceCommit: string; url: string };
    mariadb: { name: string; version: string; license: string; copyrights: string[] };
};

export const branding = __MASSDB_BRANDING__;
