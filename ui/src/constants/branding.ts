// MassDB SQL implementation.
// Licensing decision pending (A02); see dist/source-headers.json.
// This file does not assert an ASF contributor agreement.
declare const __MASSDB_BRANDING__: {
    productName: string;
    productVersion: string;
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
