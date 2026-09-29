// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Input, Modal, Tag } from 'antd';
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

function Fields({ value, names }: { value: LicenseFields; names: string[] }) {
    const { t } = useTranslation();
    return <dl className={styles.fields}>{names.map(name => <React.Fragment key={name}>
        <dt>{t(`license.fields.${name}`)}</dt>
        <dd>{['expires_at', 'not_before', 'trusted_utc'].includes(name)
            ? <TimeValue value={value[name]} /> : displayValue(value[name])}</dd>
    </React.Fragment>)}</dl>;
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

    function receiptResult(result: LicenseResponse, expectedFingerprint: string): 'complete' | 'pending' | 'invalid' {
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
                const outcome = receiptResult(result, id);
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
        setReceipt({ httpStatus: 0, retryAfterSeconds: null, body: { fingerprint: id, submission_status: 'UNKNOWN' } });
        try {
            const result = await request('/import', run, input);
            if (!result) return;
            clearInput();
            if (receiptResult(result, id) !== 'pending') return;
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
        setReceipt(null);
        setPollStatus('stopped');
        const run = generation.current;
        try {
            const result = await request(`/imports/${fingerprint}`, run);
            if (result) receiptResult(result, fingerprint);
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
                <section className={styles.card} data-testid="license-deployment"><h2>{t('license.deployment')}</h2>
                    <Fields value={snapshot} names={['deployment_id', 'highest_sequence', 'applied_version', 'clock_epoch',
                        'base_max_fe_nodes', 'base_max_be_nodes']} />
                </section>
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
                        setNotice('');
                        setError(null);
                        setPollStatus('idle');
                    }} />
                <Button data-testid="license-receipt-query" disabled={disabled || !isFingerprint(fingerprint)} onClick={queryReceipt}>
                    {t('license.queryReceipt')}</Button>
            </div>
            {receipt && <Fields value={{ ...receipt.body, http_status: receipt.httpStatus || null, retry_after: receipt.retryAfterSeconds }}
                names={['submission_status', 'reason', 'committed_version', 'applied_version', 'http_status', 'retry_after']} />}
            <p role="status" data-testid="license-poll-status" data-poll-status={pollStatus}>{t(`license.poll.${pollStatus}`)}</p>
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
