// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
import { getBasePath } from '../utils/utils';


const SAFE_REASONS = new Set([
    'ACCESS_DENIED', 'CSRF_REJECTED', 'LICENSE_ADMIN_REQUIRED', 'LICENSE_APPLIED',
    'LICENSE_BASE_CAPACITY_UNAVAILABLE', 'LICENSE_BE_LIMIT_EXCEEDED', 'LICENSE_BODY_TOO_LARGE', 'LICENSE_CERTIFICATE_EXPIRED',
    'LICENSE_CLOCK_SUSPECT', 'LICENSE_COMMITTED_PENDING_APPLY', 'LICENSE_COMMIT_UNCERTAIN', 'LICENSE_DEPLOYMENT_MISMATCH',
    'LICENSE_FEATURE_NOT_LICENSED', 'LICENSE_FE_LIMIT_EXCEEDED', 'LICENSE_FE_UPGRADE_REQUIRED', 'LICENSE_IMPORT_CONFLICT',
    'LICENSE_IMPORT_HISTORY_UNAVAILABLE', 'LICENSE_IMPORT_NOT_READY', 'LICENSE_INPUT_TOO_LARGE', 'LICENSE_INVALID_CLAIMS',
    'LICENSE_INVALID_BASE64URL', 'LICENSE_INVALID_COMPACT', 'LICENSE_INVALID_FINGERPRINT', 'LICENSE_INVALID_HEADER', 'LICENSE_INVALID_IDENTIFIER',
    'LICENSE_INVALID_JSON', 'LICENSE_INVALID_REPAIR_ID', 'LICENSE_INVALID_REQUEST', 'LICENSE_INVALID_RESPONSE',
    'LICENSE_INVALID_SIGNATURE', 'LICENSE_INVALID_TRUST_STORE', 'LICENSE_ISSUED_IN_FUTURE', 'LICENSE_KEY_STILL_REQUIRED',
    'LICENSE_MANAGEMENT_BUSY', 'LICENSE_MANAGEMENT_UNAVAILABLE', 'LICENSE_MEMBERSHIP_COMMIT_UNCERTAIN', 'LICENSE_METADATA_UNAVAILABLE',
    'LICENSE_NODE_LIMIT_TOO_SMALL', 'LICENSE_NOT_LEADER', 'LICENSE_NOT_READY', 'LICENSE_RATE_LIMITED',
    'LICENSE_RENEWAL_REDUCTION', 'LICENSE_REPAIR_CONFLICT', 'LICENSE_REPAIR_HISTORY_UNAVAILABLE', 'LICENSE_REQUEST_FAILED',
    'LICENSE_STALE_IMPORT_DECISION', 'LICENSE_SUBMISSION_UNKNOWN', 'LICENSE_UNSUPPORTED_POLICY', 'LICENSE_UNSUPPORTED_SCHEMA',
    'LICENSE_UNTRUSTED_KEY', 'LICENSE_VALIDATED', 'LICENSE_VERIFICATION_UNAVAILABLE', 'UNAUTHENTICATED',
]);
const SAFE_STATUSES = new Set(['VALID', 'EXPIRING', 'EXPIRED', 'MISSING', 'NOT_YET_VALID', 'INVALID',
    'FEATURE_NOT_LICENSED', 'CLOCK_SUSPECT', 'LICENSE_NOT_READY', 'LIMIT_EXCEEDED']);

const JSONbig = require('json-bigint')({ storeAsString: true });
export type LicenseFields = { [key: string]: any };
export interface LicenseResponse {
    httpStatus: number;
    retryAfterSeconds: number | null;
    body: LicenseFields;
}

/** Keep management HTTP semantics separate from the legacy general-purpose request helper. */
export async function licenseRequest(path: string, signal: AbortSignal, certificate?: string): Promise<LicenseResponse> {
    if (!/^(?:|\/validate|\/import|\/imports\/[0-9a-f]{64})$/.test(path)) {
        throw new Error('LICENSE_INVALID_REQUEST');
    }
    const url = new URL(`${getBasePath()}/api/license${path}`, window.location.origin);
    if (url.origin !== window.location.origin) throw new Error('LICENSE_INVALID_REQUEST');
    const response = await fetch(url.toString(), {
        method: certificate === undefined ? 'GET' : 'POST',
        credentials: 'same-origin',
        mode: 'same-origin',
        redirect: 'error',
        cache: 'no-store',
        referrerPolicy: 'same-origin',
        signal,
        headers: certificate === undefined ? { Accept: 'application/json' } : {
            Accept: 'application/json',
            'Content-Type': 'application/json; charset=utf-8',
            'X-MassDB-License-CSRF': '1',
        },
        body: certificate === undefined ? undefined : JSON.stringify({ certificate }),
    });
    // Never surface arbitrary server messages or HTML, which could contain submitted input.
    // A transport failure after headers must stop polling, not become a parseable UNKNOWN response.
    const content = await response.text();
    let body: LicenseFields;
    try {
        const contentType = response.headers.get('Content-Type') || '';
        if (!/^application\/(?:json|[a-z0-9.+-]+\+json)(?:;|$)/i.test(contentType)) throw new Error();
        if (content.length > 2 * 1024 * 1024) throw new Error();
        const decoded = JSONbig.parse(content);
        if (!decoded || Array.isArray(decoded) || typeof decoded !== 'object') throw new Error();
        body = {};
        const fields = ['administrator', 'expires_at', 'deployment_id', 'activated', 'recovery_ready',
            'reasons', 'warnings', 'trusted_utc', 'clock_epoch', 'registered_fe_nodes', 'registered_be_nodes',
            'max_fe_nodes', 'max_be_nodes', 'base_max_fe_nodes', 'base_max_be_nodes', 'active', 'pending',
            'highest_sequence', 'applied_version', 'committed_version', 'retryable', 'idempotent',
            'coverage_gap_seconds', 'expected_license_version', 'expected_membership_version',
            'license_id', 'license_version', 'sequence'];
        const booleanFields = new Set(['administrator', 'activated', 'recovery_ready', 'retryable', 'idempotent']);
        const numericFields = new Set(['expires_at', 'trusted_utc', 'clock_epoch', 'registered_fe_nodes',
            'registered_be_nodes', 'max_fe_nodes', 'max_be_nodes', 'base_max_fe_nodes', 'base_max_be_nodes',
            'highest_sequence', 'applied_version', 'committed_version', 'coverage_gap_seconds',
            'expected_license_version', 'expected_membership_version', 'license_version', 'sequence']);
        fields.forEach(key => {
            if (!Object.prototype.hasOwnProperty.call(decoded, key)) return;
            const value = decoded[key];
            if (booleanFields.has(key)) {
                if (typeof value === 'boolean') body[key] = value;
            } else if (numericFields.has(key)) {
                body[key] = value === null || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
                    || (typeof value === 'string' && /^(?:0|[1-9]\d{0,18})$/.test(value)) ? value : null;
            } else {
                body[key] = value;
            }
        });
        if (SAFE_STATUSES.has(decoded.status)) body.status = decoded.status;
        if (typeof decoded.reason === 'string') body.reason = SAFE_REASONS.has(decoded.reason)
            ? decoded.reason : 'LICENSE_REQUEST_FAILED';
        if (['NOT_SUBMITTED', 'COMMITTED', 'APPLIED', 'UNKNOWN'].includes(decoded.submission_status)) {
            body.submission_status = decoded.submission_status;
        }
        if (typeof decoded.fingerprint === 'string' && /^[0-9a-f]{64}$/.test(decoded.fingerprint)) {
            body.fingerprint = decoded.fingerprint;
        }
    } catch (_) {
        body = { reason: 'LICENSE_INVALID_RESPONSE' };
    }
    if (path === '/import' && body.submission_status === undefined) body.submission_status = 'UNKNOWN';
    const retry = response.headers.get('Retry-After');
    return {
        httpStatus: response.status,
        retryAfterSeconds: retry && /^\d{1,6}$/.test(retry) ? Number(retry) : null,
        body,
    };
}
