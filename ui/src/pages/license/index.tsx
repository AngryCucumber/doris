// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Input, Modal, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { LicenseFields, LicenseResponse, licenseRequest } from '../../api/license';
import { SESSION_CHANNEL, SESSION_EVENT } from '../../utils/session-events';
import {
    MAX_CERTIFICATE_BYTES, POLL_BUDGET, POLL_DELAYS, appliedReceipt, certificateFingerprint,
    displayValue, isFingerprint, timestamp, utf8Bytes,
} from './model';
import styles from './index.less';

function TimeValue({ value }: { value: any }) {
    const { t } = useTranslation();
    const time = timestamp(value);
    return time ? <span><span>{time.utc}</span><small>{t('license.localTime')}: {time.local}</small></span> : <span>—</span>;
}

const TIME_FIELDS = ['expires_at', 'not_before', 'trusted_utc', 'confirmed_utc'];

function Fields({ value, names }: { value: LicenseFields; names: string[] }) {
    const { t } = useTranslation();
    return <dl className={styles.fields}>{names.map(name => <React.Fragment key={name}>
        <dt>{t(`license.fields.${name}`)}</dt>
        <dd>{TIME_FIELDS.includes(name) ? <TimeValue value={value[name]} />
            : typeof value[name] === 'boolean' ? t(`license.boolean.${value[name]}`) : displayValue(value[name])}</dd>
    </React.Fragment>)}</dl>;
}

function changeText(change: LicenseFields): { [key: string]: any } {
    const previous = timestamp(change.previous_expires_at);
    const current = timestamp(change.expires_at);
    return {
        previous: previous ? previous.utc : displayValue(change.previous_expires_at),
        current: current ? current.utc : displayValue(change.expires_at),
        gap: displayValue(change.gap_seconds), previousLimit: displayValue(change.previous_limit),
        limit: displayValue(change.limit), licenseId: displayValue(change.license_id),
        sequence: displayValue(change.sequence), features: displayValue(change.features),
    };
}

/** Server facts about what a replacement changes; they inform the operator and never change admission. */
function ChangeList({ changes, testId }: { changes: any; testId: string }) {
    const { t } = useTranslation();
    if (!Array.isArray(changes)) return null;
    return <div className={styles.changes} data-testid={testId}
        data-change-codes={changes.map(change => change.code).join(',')}>
        {changes.length === 0 ? <p className={styles.muted}>{t('license.changes.none')}</p> : <>
            <Alert type="warning" showIcon message={t('license.changes.title')} description={t('license.changes.warning')} />
            <ul>{changes.map((change, index) => <li key={index} data-change-code={change.code}>
                <Tag color="orange">{change.code}</Tag>
                <span>{t(`license.changes.codes.${change.code}`, { defaultValue: change.code, ...changeText(change) })}</span>
            </li>)}</ul>
        </>}
    </div>;
}

function CertificateCard({ name, certificate }: { name: string; certificate: LicenseFields | null }) {
    const { t } = useTranslation();
    return <section className={styles.card} data-testid={`license-${name}`}>
        <h2>{t(`license.${name}`)}</h2>
        {certificate ? <Fields value={certificate} names={[
            'license_id', 'customer_id', 'issuer', 'edition', 'sequence', 'not_before', 'expires_at',
            'max_fe_nodes', 'max_be_nodes', 'features', 'fingerprint',
        ]} /> : <p className={styles.muted}>{t('license.noCertificate')}</p>}
    </section>;
}

/** One labelled fact with a plain-language note under it. */
function Fact({ name, help, children }: { name: string; help?: string; children: React.ReactNode }) {
    const { t } = useTranslation();
    return <>
        <dt>{t(`license.fields.${name}`)}</dt>
        <dd data-field={name}>{children}{help && <small>{help}</small>}</dd>
    </>;
}

function seconds(value: any): number | null {
    const number = Number(value);
    return value !== null && value !== undefined && Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}

/** Facts that identify this cluster's licensing: what an operator quotes to the issuer or checks before an import. */
function DeploymentCard({ snapshot }: { snapshot: LicenseFields }) {
    const { t } = useTranslation();
    const id = typeof snapshot.deployment_id === 'string' && snapshot.deployment_id ? snapshot.deployment_id : null;
    const fe = snapshot.base_max_fe_nodes;
    const be = snapshot.base_max_be_nodes;
    return <section className={styles.card} data-testid="license-deployment"><h2>{t('license.deployment')}</h2>
        <dl className={styles.fields}>
            <Fact name="deployment_id" help={t('license.help.deployment_id')}>
                {id ? <Typography.Text copyable={{ text: id }} data-testid="license-deployment-id">{id}</Typography.Text> : '—'}
            </Fact>
            <Fact name="highest_sequence" help={t('license.help.highest_sequence')}>{displayValue(snapshot.highest_sequence)}</Fact>
            <Fact name="clock_epoch" help={t('license.help.clock_epoch')}>{displayValue(snapshot.clock_epoch)}</Fact>
            <Fact name="expansion_limit" help={t('license.help.expansion_limit')}>
                {fe === null || fe === undefined || be === null || be === undefined ? '—'
                    : t('license.expansionLimit', { fe: displayValue(fe), be: displayValue(be) })}
            </Fact>
        </dl>
    </section>;
}

/**
 * The state of this FE's license time in one sentence, from the same facts the server reports. Rejection follows
 * LicenseClock.isSuspect(): a committed suspicion everywhere, a local one only on the master after its settling period.
 */
function clockState(snapshot: LicenseFields): string {
    if (snapshot.confirmed_utc === null || snapshot.confirmed_utc === undefined) return 'unavailable';
    if (snapshot.clock_committed_suspect === true) return 'committed';
    if (snapshot.clock_local_suspect === true) {
        if (snapshot.clock_enforced !== true) return 'slowReported';
        return snapshot.clock_settled === true ? 'rejecting' : 'slowSettling';
    }
    if ((seconds(snapshot.clock_pending_forward_seconds) || 0) === 0) return 'normal';
    // A boot clock ahead of the record already counts for this FE's admission; an in-process jump does not.
    return snapshot.clock_pending_startup === true ? 'pendingStartup' : 'pending';
}

const CLOCK_ALERT: { [state: string]: 'success' | 'info' | 'warning' | 'error' } = {
    normal: 'success', pending: 'info', pendingStartup: 'info', unavailable: 'info', slowReported: 'warning', slowSettling: 'warning',
    rejecting: 'error', committed: 'error',
};

/** This FE's license time: a one-sentence state, then the facts behind it in plain words. */
function ClockCard({ snapshot }: { snapshot: LicenseFields }) {
    const { t } = useTranslation();
    const duration = (value: any) => {
        const total = seconds(value);
        if (total === null) return displayValue(value);
        const h = Math.floor(total / 3600);
        const m = Math.floor((total % 3600) / 60);
        const s = total % 60;
        return h > 0 ? t('license.duration.hours', { h, m }) : m > 0 ? t('license.duration.minutes', { m, s })
            : t('license.duration.seconds', { s });
    };
    const yesNo = (value: any) => typeof value === 'boolean' ? t(`license.boolean.${value}`) : '—';
    const state = clockState(snapshot);
    const forward = seconds(snapshot.clock_pending_forward_seconds) || 0;
    const verdict = typeof snapshot.clock_peer_verdict === 'string'
        ? t(`license.verdict.${snapshot.clock_peer_verdict}`, { defaultValue: snapshot.clock_peer_verdict }) : '—';
    return <section className={styles.card} data-testid="license-clock"><h2>{t('license.clock')}</h2>
        <Alert type={CLOCK_ALERT[state]} showIcon data-testid="license-clock-state" data-clock-state={state}
            message={t(`license.clockStates.${state}`, { forward: duration(forward),
                age: duration(snapshot.clock_pending_age_seconds) })} />
        <dl className={styles.fields}>
            <Fact name="confirmed_utc" help={t('license.help.confirmed_utc')}><TimeValue value={snapshot.confirmed_utc} /></Fact>
            <Fact name="clock_peer_verdict">{verdict}</Fact>
            <Fact name="clock_local_suspect" help={t('license.help.clock_local_suspect')}>{yesNo(snapshot.clock_local_suspect)}</Fact>
            <Fact name="clock_committed_suspect" help={t('license.help.clock_committed_suspect')}>
                {yesNo(snapshot.clock_committed_suspect)}</Fact>
            <Fact name="clock_enforced" help={t('license.help.clock_enforced')}>{yesNo(snapshot.clock_enforced)}</Fact>
            <Fact name="clock_settled" help={t('license.help.clock_settled')}>
                {typeof snapshot.clock_settled === 'boolean' ? t(`license.settled.${snapshot.clock_settled}`) : '—'}</Fact>
            {forward > 0 && <Fact name="clock_pending_forward_seconds">
                {t('license.pendingForward', { forward: duration(forward), age: duration(snapshot.clock_pending_age_seconds) })}
                {snapshot.clock_pending_startup === true && t('license.pendingStartup')}</Fact>}
        </dl>
        <p className={styles.muted}>{t('license.clockHint')}</p>
    </section>;
}

function gapSeconds(value: any): number | null {
    const millis = Number(value);
    return Number.isFinite(millis) && millis >= 0 ? Math.floor(millis / 1000) : null;
}

const SUBMISSION_STATES = ['APPLIED', 'COMMITTED', 'NOT_SUBMITTED', 'UNKNOWN'];

/**
 * A receipt in one sentence: whether that import took effect and what to do next. The codes and versions stay on one
 * line below it for support; they are what SHOW LICENSE IMPORT and the API return.
 */
function ReceiptResult({ receipt }: { receipt: LicenseResponse }) {
    const { t, i18n } = useTranslation();
    const body = receipt.body;
    const status = typeof body.submission_status === 'string' && SUBMISSION_STATES.includes(body.submission_status)
        ? body.submission_status : null;
    const reason = typeof body.reason === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(body.reason) ? body.reason : null;
    const explained = status === 'NOT_SUBMITTED' && reason && i18n.exists(`license.errors.${reason}`)
        ? t(`license.errors.${reason}`) : '';
    const details = [displayValue(body.submission_status), reason,
        body.committed_version !== undefined && body.committed_version !== null
            ? `${t('license.fields.committed_version')} ${displayValue(body.committed_version)}` : null,
        body.applied_version !== undefined && body.applied_version !== null
            ? `${t('license.fields.applied_version')} ${displayValue(body.applied_version)}` : null,
        receipt.httpStatus ? `HTTP ${receipt.httpStatus}` : null].filter(Boolean).join(' \u00b7 ');
    return <div className={styles.changes} data-testid="license-receipt-result" data-receipt-state={status || 'OTHER'}>
        <Alert type={status === 'APPLIED' ? 'success' : status === 'NOT_SUBMITTED' ? 'error'
            : status === 'COMMITTED' ? 'info' : 'warning'} showIcon
            message={t(`license.receiptStates.${status || 'OTHER'}`)} description={explained || undefined} />
        {receipt.retryAfterSeconds !== null && <p>{t('license.receiptRetry', { seconds: receipt.retryAfterSeconds })}</p>}
        <p className={styles.muted}>{t('license.receiptDetails', { details })}</p>
    </div>;
}

const SLOT_REASONS = ['UNTRUSTED_KEY', 'INVALID_SIGNATURE', 'DEPLOYMENT_MISMATCH', 'SEQUENCE_ABOVE_HIGHEST',
    'VERSION_ABOVE_LICENSE_VERSION', 'INVALID_SLOT', 'VERIFICATION_UNAVAILABLE', 'UNSUPPORTED_SCHEMA', 'UNSUPPORTED_POLICY',
    'INVALID_COMPACT', 'INVALID_JSON', 'INVALID_HEADER', 'INVALID_CLAIMS'];
const GAP_KINDS = ['FORCE_SKIP_JOURNAL_ID', 'REPLAY_EXCEPTION_SKIPPED', 'IMAGE_MODULE_MISSING', 'RECORD_VERSION_GAP',
    'DEPLOYMENT_RESET', 'LEGACY_IMAGE_FLAG'];

function count(value: any): number {
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : 0;
}

/**
 * Whether this FE can verify every certificate and has every license record, in one sentence, then the facts. The
 * codes stay next to the plain words: they are what fe.log and SHOW LICENSE print. Facts only, no actions.
 */
function DiagnosticsCard({ snapshot }: { snapshot: LicenseFields }) {
    const { t } = useTranslation();
    const slots: LicenseFields[] = Array.isArray(snapshot.invalid_slots) ? snapshot.invalid_slots : [];
    const gaps: LicenseFields[] = Array.isArray(snapshot.recent_replay_gaps) ? snapshot.recent_replay_gaps : [];
    const state = slots.length > 0 ? 'needsAction'
        : count(snapshot.replay_gaps) > 0 || count(snapshot.ignored_records) > 0 || gaps.length > 0 ? 'notice' : 'normal';
    const digest = typeof snapshot.trust_sha256 === 'string' && /^[0-9a-f]{64}$/.test(snapshot.trust_sha256)
        ? snapshot.trust_sha256 : null;
    return <section className={styles.card} data-testid="license-diagnostics"><h2>{t('license.diagnostics')}</h2>
        <Alert type={state === 'needsAction' ? 'error' : state === 'notice' ? 'warning' : 'success'} showIcon
            data-testid="license-diagnostics-state" data-diagnostics-state={state}
            message={t(`license.diagnosticsStates.${state}`, { count: slots.length })} />
        <dl className={styles.fields}>
            <Fact name="trust_sha256" help={t('license.help.trust_sha256')}>
                {digest ? <Typography.Text copyable={{ text: digest }} data-testid="license-trust-digest">
                    {digest.slice(0, 12)}…</Typography.Text> : '—'}
            </Fact>
            <Fact name="replay_gaps" help={t('license.help.replay_gaps')}>{displayValue(snapshot.replay_gaps)}</Fact>
            <Fact name="ignored_records" help={t('license.help.ignored_records')}>{displayValue(snapshot.ignored_records)}</Fact>
        </dl>
        <h3>{t('license.invalidSlots')}</h3>
        {slots.length === 0 ? <p className={styles.muted}>{t('license.noInvalidSlots')}</p> : <div className={styles.changes}>
            <Alert type="warning" showIcon message={t('license.invalidSlotsWarning')} />
            <ul data-testid="license-invalid-slots">{slots.map((slot, index) => <li key={index}>
                <Tag color="red">{t(`license.slotReasons.${SLOT_REASONS.includes(slot.reason) ? slot.reason : 'OTHER'}`)}</Tag>
                <span>{t('license.slotLine', { slot: t(`license.slots.${slot.slot}`, { defaultValue: slot.slot }),
                    code: slot.reason, keyId: displayValue(slot.key_id) })}</span>
            </li>)}</ul>
        </div>}
        <h3>{t('license.recentReplayGaps')}</h3>
        {gaps.length === 0 ? <p className={styles.muted}>{t('license.noReplayGaps')}</p> : <div className={styles.changes}>
            <ul data-testid="license-replay-gaps">{gaps.map((gap, index) => {
                const time = timestamp(gapSeconds(gap.wall_millis));
                const journal = Number(gap.journal_id);
                return <li key={index}>
                    <Tag color="orange">{t(`license.gapKinds.${GAP_KINDS.includes(gap.kind) ? gap.kind : 'OTHER'}`)}</Tag>
                    <span>{Number.isFinite(journal) && journal >= 0
                        ? `${t('license.gapLine', { journal: displayValue(gap.journal_id), opCode: displayValue(gap.op_code) })} \u00b7 ` : ''}
                        {gap.kind}{time ? ` \u00b7 ${time.utc}` : ''}</span>
                </li>;
            })}</ul>
        </div>}
    </section>;
}

export default function LicensePage() {
    const { t } = useTranslation();
    const [snapshot, setSnapshot] = useState<LicenseFields | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<LicenseResponse | null>(null);
    const [notice, setNotice] = useState('');
    const [dialog, setDialog] = useState(false);
    const [input, setInput] = useState('');
    const [validation, setValidation] = useState<LicenseResponse | null>(null);
    const [fingerprint, setFingerprint] = useState('');
    const [receipt, setReceipt] = useState<LicenseResponse | null>(null);
    // Import responses carry the committed decision's changes; receipt queries do not, so keep them apart.
    const [importChanges, setImportChanges] = useState<LicenseFields[] | null>(null);
    const [pollStatus, setPollStatus] = useState('idle');
    const [cooldown, setCooldown] = useState(0);
    const mounted = useRef(false);
    const generation = useRef(0);
    const busyRef = useRef(false);
    const controller = useRef<AbortController | null>(null);
    const timer = useRef<number | null>(null);
    const deadlineTimer = useRef<number | null>(null);
    const cooldownTimer = useRef<number | null>(null);
    const retryAt = useRef(0);
    const fileInput = useRef<HTMLInputElement | null>(null);
    const fileReader = useRef<FileReader | null>(null);
    const inputGeneration = useRef(0);
    const administrator = snapshot !== null && snapshot.administrator === true;

    function clearInput() {
        inputGeneration.current++;
        if (fileReader.current && fileReader.current.readyState === FileReader.LOADING) fileReader.current.abort();
        fileReader.current = null;
        if (fileInput.current) fileInput.current.value = '';
        setInput('');
        setValidation(null);
        setDialog(false);
    }

    function cancelWork() {
        generation.current++;
        if (timer.current !== null) window.clearTimeout(timer.current);
        if (deadlineTimer.current !== null) window.clearTimeout(deadlineTimer.current);
        timer.current = null;
        deadlineTimer.current = null;
        if (controller.current) controller.current.abort();
        controller.current = null;
        busyRef.current = false;
        if (mounted.current) setBusy(false);
    }

    function clearSession() {
        cancelWork();
        clearInput();
        setSnapshot(null);
        setReceipt(null);
        setImportChanges(null);
        setFingerprint('');
        setError(null);
        setPollStatus('stopped');
        setNotice('sessionChanged');
        if (cooldownTimer.current !== null) window.clearTimeout(cooldownTimer.current);
        cooldownTimer.current = null;
        retryAt.current = 0;
        setCooldown(0);
    }

    function retainRetryAfter(response: LicenseResponse) {
        if (response.retryAfterSeconds === null || response.retryAfterSeconds <= 0) return;
        retryAt.current = Math.max(retryAt.current, performance.now() + response.retryAfterSeconds * 1000);
        setCooldown(response.retryAfterSeconds);
        if (cooldownTimer.current !== null) window.clearTimeout(cooldownTimer.current);
        cooldownTimer.current = window.setTimeout(() => {
            if (mounted.current) setCooldown(0);
        }, Math.max(0, retryAt.current - performance.now()));
    }

    async function request(path: string, run: number, certificate?: string): Promise<LicenseResponse | null> {
        if (busyRef.current || !mounted.current || run !== generation.current) return null;
        const abort = new AbortController();
        controller.current = abort;
        busyRef.current = true;
        setBusy(true);
        // Every individual request is bounded; the polling deadline can abort it earlier.
        const timeout = window.setTimeout(() => abort.abort(), 30000);
        try {
            const response = await licenseRequest(path, abort.signal, certificate);
            if (!mounted.current || run !== generation.current) return null;
            retainRetryAfter(response);
            if (response.httpStatus === 401 || response.httpStatus === 403) {
                clearSession();
                setError(response);
                return null;
            }
            return response;
        } finally {
            window.clearTimeout(timeout);
            if (run === generation.current) {
                controller.current = null;
                busyRef.current = false;
                if (mounted.current) setBusy(false);
            }
        }
    }

    function networkFailure(run: number) {
        if (!mounted.current || run !== generation.current) return;
        cancelWork();
        clearInput();
        setError({ httpStatus: 0, retryAfterSeconds: null, body: { reason: 'LICENSE_NETWORK_ERROR' } });
        setPollStatus('stopped');
    }

    async function refresh() {
        if (busyRef.current || performance.now() < retryAt.current) return;
        cancelWork();
        const run = generation.current;
        setSnapshot(null);
        clearInput();
        setError(null);
        setNotice('');
        setPollStatus('stopped');
        try {
            const result = await request('', run);
            if (!result) return;
            if (result.httpStatus === 200 && typeof result.body.administrator === 'boolean'
                && typeof result.body.status === 'string') {
                // Never retain prior ADMIN fields when a session becomes an ordinary Web user.
                const value = result.body;
                setSnapshot(value.administrator ? value : {
                    administrator: false, status: value.status, expires_at: value.expires_at,
                });
                if (!value.administrator) {
                    setReceipt(null);
                    setImportChanges(null);
                    setFingerprint('');
                }
            } else {
                setError(result);
            }
        } catch (_) { networkFailure(run); }
    }

    useEffect(() => {
        mounted.current = true;
        refresh();
        const stop = () => {
            cancelWork();
            clearInput();
            setPollStatus('stopped');
        };
        const visibility = () => { if (document.hidden) stop(); };
        const storage = (event: StorageEvent) => {
            if (event.key === 'username' || event.key === null) clearSession();
        };
        const channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(SESSION_CHANNEL);
        if (channel) channel.onmessage = clearSession;
        window.addEventListener(SESSION_EVENT, clearSession);
        window.addEventListener('storage', storage);
        window.addEventListener('offline', stop);
        window.addEventListener('pagehide', stop);
        document.addEventListener('visibilitychange', visibility);
        return () => {
            mounted.current = false;
            cancelWork();
            inputGeneration.current++;
            if (fileReader.current && fileReader.current.readyState === FileReader.LOADING) fileReader.current.abort();
            if (fileInput.current) fileInput.current.value = '';
            if (cooldownTimer.current !== null) window.clearTimeout(cooldownTimer.current);
            if (channel) channel.close();
            window.removeEventListener(SESSION_EVENT, clearSession);
            window.removeEventListener('storage', storage);
            window.removeEventListener('offline', stop);
            window.removeEventListener('pagehide', stop);
            document.removeEventListener('visibilitychange', visibility);
        };
    }, []);

    function inputError(reason: string) {
        setError({ httpStatus: 0, retryAfterSeconds: null, body: { reason } });
        setValidation(null);
    }

    function editInput(value: string) {
        inputGeneration.current++;
        setValidation(null);
        setError(null);
        if (utf8Bytes(value).length > MAX_CERTIFICATE_BYTES) {
            setInput('');
            inputError('LICENSE_INPUT_TOO_LARGE');
        } else {
            setInput(value);
        }
    }

    function readFile(event: React.ChangeEvent<HTMLInputElement>) {
        const file = event.target.files && event.target.files[0];
        editInput('');
        if (!file) return;
        if (file.size > MAX_CERTIFICATE_BYTES) {
            event.target.value = '';
            inputError('LICENSE_INPUT_TOO_LARGE');
            return;
        }
        const version = inputGeneration.current;
        const reader = new FileReader();
        fileReader.current = reader;
        reader.onload = () => {
            if (!mounted.current || version !== inputGeneration.current) return;
            fileReader.current = null;
            try {
                const value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(reader.result as ArrayBuffer);
                editInput(value);
            } catch (_) { inputError('LICENSE_INVALID_FILE'); }
        };
        reader.onerror = () => {
            if (mounted.current && version === inputGeneration.current) inputError('LICENSE_INVALID_FILE');
        };
        reader.readAsArrayBuffer(file);
    }

    async function validate() {
        if (!administrator || busyRef.current || performance.now() < retryAt.current) return;
        if (!input || utf8Bytes(input).length > MAX_CERTIFICATE_BYTES) {
            inputError(input ? 'LICENSE_INPUT_TOO_LARGE' : 'LICENSE_INPUT_REQUIRED');
            return;
        }
        const run = generation.current;
        const version = inputGeneration.current;
        setValidation(null);
        setError(null);
        const expectedFingerprint = certificateFingerprint(input);
        try {
            const result = await request('/validate', run, input);
            if (!result || version !== inputGeneration.current) return;
            if (result.httpStatus === 200 && result.body.reason === 'LICENSE_VALIDATED'
                && result.body.fingerprint === expectedFingerprint) {
                setValidation(result);
            } else {
                setError(result.httpStatus === 200 ? { ...result, body: { reason: 'LICENSE_INVALID_RESPONSE' } } : result);
            }
        } catch (_) { networkFailure(run); }
    }

    // query: the response answers a receipt query, not the import request itself.
    function receiptResult(result: LicenseResponse, expectedFingerprint: string,
        query = false): 'complete' | 'pending' | 'invalid' {
        const body = result.body;
        const acknowledged = body.submission_status === 'COMMITTED' || body.submission_status === 'APPLIED';
        if ((body.fingerprint !== undefined && body.fingerprint !== expectedFingerprint)
            || (acknowledged && body.fingerprint !== expectedFingerprint)
            || (body.submission_status === 'APPLIED' && (result.httpStatus !== 200 || !appliedReceipt(body)))) {
            const invalid = { ...result, body: { reason: 'LICENSE_INVALID_RESPONSE',
                submission_status: 'UNKNOWN', fingerprint: expectedFingerprint } };
            setReceipt(invalid);
            setError(invalid);
            setPollStatus('stopped');
            return 'invalid';
        }
        if (query && result.httpStatus >= 400 && body.fingerprint === undefined) {
            // A failure that names no fingerprint (a follower without a reachable master answers 503 NOT_SUBMITTED)
            // says nothing about this submission: keep the receipt and tell the operator not to import it again.
            setError(result);
            setNotice('receiptUnconfirmed');
            return 'pending';
        }
        setReceipt(result);
        if (appliedReceipt(result.body) && result.httpStatus === 200) {
            setPollStatus('complete');
            setNotice('appliedRefresh');
            clearInput();
            setError(null);
            return 'complete';
        }
        if (result.httpStatus >= 400) setError(result);
        return 'pending';
    }

    function startPolling(id: string, initial: LicenseResponse) {
        const run = generation.current;
        const start = performance.now();
        let index = 0;
        function stop(status: string) {
            if (run !== generation.current) return;
            cancelWork();
            setPollStatus(status);
        }
        async function poll() {
            if (run !== generation.current || !mounted.current) return;
            if (document.hidden || !navigator.onLine) { stop('stopped'); return; }
            if (performance.now() - start >= POLL_BUDGET) { stop('exhausted'); return; }
            try {
                const result = await request(`/imports/${id}`, run);
                if (!result) return;
                const outcome = receiptResult(result, id, true);
                if (outcome !== 'pending') { stop(outcome === 'complete' ? 'complete' : 'stopped'); return; }
                const state = result.body.submission_status;
                if (state !== 'COMMITTED' && state !== 'UNKNOWN' && result.httpStatus !== 429) {
                    stop('stopped'); return;
                }
                schedule();
            } catch (_) { networkFailure(run); }
        }
        function schedule() {
            if (run !== generation.current || document.hidden || !navigator.onLine) { stop('stopped'); return; }
            const delay = Math.max(POLL_DELAYS[Math.min(index++, POLL_DELAYS.length - 1)], retryAt.current - performance.now());
            if (performance.now() + delay >= start + POLL_BUDGET) return;
            timer.current = window.setTimeout(poll, delay);
        }
        retainRetryAfter(initial);
        setPollStatus('waiting');
        deadlineTimer.current = window.setTimeout(() => stop('exhausted'), POLL_BUDGET);
        schedule();
    }

    async function importCertificate() {
        if (!administrator || !validation || busyRef.current || performance.now() < retryAt.current) return;
        const id = certificateFingerprint(input);
        if (id !== validation.body.fingerprint) { setValidation(null); return; }
        const run = generation.current;
        setError(null);
        setNotice('');
        setPollStatus('idle');
        setFingerprint(id);
        setImportChanges(null);
        setReceipt({ httpStatus: 0, retryAfterSeconds: null, body: { fingerprint: id, submission_status: 'UNKNOWN' } });
        try {
            const result = await request('/import', run, input);
            if (!result) return;
            clearInput();
            const outcome = receiptResult(result, id);
            const acknowledged = result.body.submission_status === 'APPLIED' || result.body.submission_status === 'COMMITTED';
            if (outcome !== 'invalid' && acknowledged && Array.isArray(result.body.changes)) {
                setImportChanges(result.body.changes);
            }
            if (outcome !== 'pending') return;
            if (result.body.submission_status === 'COMMITTED' || result.body.submission_status === 'UNKNOWN') {
                startPolling(id, result);
            } else {
                setPollStatus('stopped');
                setError(result);
            }
        } catch (_) { networkFailure(run); }
    }

    async function queryReceipt() {
        if (!administrator || busyRef.current || !isFingerprint(fingerprint) || performance.now() < retryAt.current) return;
        cancelWork();
        setError(null);
        setNotice('');
        // A receipt on screen for this same fingerprint stays until the answer replaces it: a failure that says
        // nothing about the submission must not take it away. A receipt for another fingerprint is cleared.
        if (!receipt || receipt.body.fingerprint !== fingerprint) setReceipt(null);
        setPollStatus('stopped');
        const run = generation.current;
        try {
            const result = await request(`/imports/${fingerprint}`, run);
            if (result) receiptResult(result, fingerprint, true);
        } catch (_) { networkFailure(run); }
    }

    const errorReason = error && typeof error.body.reason === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(error.body.reason)
        ? error.body.reason : 'LICENSE_REQUEST_FAILED';
    const disabled = busy || cooldown > 0;
    const errorPanel = error && <div data-testid="license-error" role="alert" className={styles.alert}>
            <Alert type="error" showIcon message={t(`license.errors.${errorReason}`, { defaultValue: t('license.requestFailed') })}
                description={<span>{errorReason}{error.httpStatus > 0 ? ` · HTTP ${error.httpStatus}` : ''}
                    {error.retryAfterSeconds !== null && ` · ${t('license.retryAfter', { seconds: error.retryAfterSeconds })}`}
                    {error.httpStatus === 401 && <> · <Link to="/login">{t('license.signIn')}</Link></>}</span>} />
        </div>;
    return <main className={styles.page} data-testid="license-page">
        <div className={styles.heading}>
            <div><h1>{t('license.title')}</h1><p>{t('license.intro')}</p></div>
            <div className={styles.actions}>
                <Button data-testid="license-refresh" disabled={disabled} onClick={refresh}>{t('license.refresh')}</Button>
                {administrator && <Button type="primary" data-testid="license-import-open" disabled={disabled || pollStatus === 'waiting'}
                    onClick={() => { clearInput(); setError(null); setDialog(true); }}>{t('license.import')}</Button>}
            </div>
        </div>
        {notice && <Alert className={styles.alert} type="info" message={t(`license.${notice}`)} />}
        {!dialog && errorPanel}
        {cooldown > 0 && <p role="status">{t('license.retryAfter', { seconds: cooldown })}</p>}
        {!snapshot && !error && <p role="status">{busy ? t('license.loading') : t('license.refreshRequired')}</p>}
        {snapshot && <>
            <section className={styles.card}>
                <div className={styles.statusLine}><h2>{t('license.serverStatus')}</h2>
                    <Tag color={snapshot.status === 'VALID' ? 'green' : 'orange'} data-testid="license-status" data-status={snapshot.status}>
                        {t(`license.states.${snapshot.status}`, { defaultValue: snapshot.status })}
                    </Tag>
                </div>
                <Fields value={snapshot} names={['expires_at']} />
                {administrator ? <>
                    <Fields value={snapshot} names={['reasons', 'warnings', 'trusted_utc', 'recovery_ready', 'activated']} />
                    <div className={styles.usage}>
                        <div data-testid="license-fe-usage"><strong>FE</strong><span>{displayValue(snapshot.registered_fe_nodes)} / {displayValue(snapshot.max_fe_nodes)}</span></div>
                        <div data-testid="license-be-usage"><strong>BE</strong><span>{displayValue(snapshot.registered_be_nodes)} / {displayValue(snapshot.max_be_nodes)}</span></div>
                    </div>
                    <p className={styles.muted}>{t('license.usageHint')}</p>
                </> : <p className={styles.muted}>{t('license.readOnly')}</p>}
            </section>
            {administrator && <>
                <div className={styles.columns}>
                    <CertificateCard name="active" certificate={snapshot.active} />
                    <CertificateCard name="pending" certificate={snapshot.pending} />
                </div>
                <div className={styles.columns}>
                    <DeploymentCard snapshot={snapshot} />
                    <ClockCard snapshot={snapshot} />
                </div>
                <DiagnosticsCard snapshot={snapshot} />
            </>}
        </>}
        {administrator && <section className={styles.card} data-testid="license-receipt"
            data-submission-status={receipt ? receipt.body.submission_status : ''}>
            <h2>{t('license.receipt')}</h2><p>{t('license.receiptHelp')}</p>
            <label htmlFor="license-fingerprint">{t('license.fields.fingerprint')}</label>
            <div className={styles.receiptActions}>
                <Input id="license-fingerprint" data-testid="license-receipt-fingerprint" value={fingerprint} maxLength={64}
                    autoComplete="off" disabled={busy || pollStatus === 'waiting'}
                    onChange={event => {
                        setFingerprint(event.target.value.toLowerCase().replace(/[^0-9a-f]/g, ''));
                        setReceipt(null);
                        setImportChanges(null);
                        setNotice('');
                        setError(null);
                        setPollStatus('idle');
                    }} />
                <Button data-testid="license-receipt-query" disabled={disabled || !isFingerprint(fingerprint)} onClick={queryReceipt}>
                    {t('license.queryReceipt')}</Button>
            </div>
            {receipt && <ReceiptResult receipt={receipt} />}
            {importChanges && <ChangeList changes={importChanges} testId="license-import-changes" />}
            {/* Refreshing or closing the dialog also stops checking: with no result on screen there is nothing to say,
                and a completed check repeats the result above. */}
            <p role="status" data-testid="license-poll-status" data-poll-status={pollStatus}
                hidden={pollStatus === 'idle' || pollStatus === 'complete' || (pollStatus === 'stopped' && !receipt)}>
                {t(`license.poll.${pollStatus}`)}</p>
        </section>}
        <Modal visible={dialog && administrator} title={t('license.import')} destroyOnClose maskClosable={false}
            onCancel={() => { cancelWork(); clearInput(); setPollStatus('stopped'); }} footer={null}>
            <div data-testid="license-import-dialog">
                {errorPanel}
                <p>{t('license.importHelp')}</p>
                <label htmlFor="license-file">{t('license.file')}</label>
                <input id="license-file" ref={fileInput} type="file" data-testid="license-certificate-file" disabled={disabled} onChange={readFile} />
                <label htmlFor="license-input">{t('license.text')}</label>
                <Input.TextArea id="license-input" data-testid="license-certificate-input" value={input} rows={7}
                    autoComplete="off" spellCheck={false} disabled={disabled} onChange={event => editInput(event.target.value)} />
                <p className={styles.muted}>{t('license.memoryOnly')}</p>
                {validation && <div data-testid="license-validation" className={styles.validation}>
                    <Alert type="success" message={t('license.validated')} />
                    <Fields value={validation.body} names={['fingerprint', 'coverage_gap_seconds', 'idempotent',
                        'expected_license_version', 'expected_membership_version']} />
                    <ChangeList changes={validation.body.changes} testId="license-validation-changes" />
                    <p>{t('license.confirmHelp')}</p>
                </div>}
                <div className={styles.actions}>
                    <Button data-testid="license-import-cancel" onClick={() => { cancelWork(); clearInput(); setPollStatus('stopped'); }}>{t('license.cancel')}</Button>
                    <Button data-testid="license-validate" disabled={disabled || !input} onClick={validate}>{t('license.validate')}</Button>
                    <Button type="primary" data-testid="license-confirm-import" disabled={disabled || !validation} onClick={importCertificate}>
                        {t('license.confirm')}</Button>
                </div>
            </div>
        </Modal>
    </main>;
}
