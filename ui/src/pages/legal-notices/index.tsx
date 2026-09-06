// MassDB SQL implementation.
// Licensing decision pending (A02); see dist/source-headers.json.
// This file does not assert an ASF contributor agreement.
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import LegalFooter from 'Components/legal-footer';
import { branding } from 'Src/constants/branding';
import { getBasePath, checkLogin } from 'Src/utils/utils';
import styles from './index.less';

function NoticeReader({ file, label }: { file: string; label: string }) {
    const { t } = useTranslation();
    const [expanded, setExpanded] = useState(false);
    const [text, setText] = useState('');
    const [error, setError] = useState(false);
    const url = `${getBasePath()}/legal/${file}`;
    useEffect(() => {
        if (!expanded) return;
        let active = true;
        setError(false);
        setText('');
        fetch(url).then(async response => {
            const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
            const body = await response.text();
            if (!response.ok || contentType !== 'text/plain' || !body.trim()
                || /<html[\s>]/i.test(body.slice(0, 1000))) {
                throw new Error('Notice unavailable');
            }
            if (active) setText(body);
        }).catch(() => { if (active) setError(true); });
        return () => { active = false; };
    }, [expanded, url]);
    return (
        <section className={styles.reader}>
            <div className={styles.readerActions}>
                <button type="button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{label}</button>
                <a href={url} download>{t('legal.download')}</a>
            </div>
            {expanded && (error ? <p role="alert">{t('legal.readError')}</p>
                : <pre tabIndex={0}>{text || t('legal.loading')}</pre>)}
        </section>
    );
}

export default function LegalNotices() {
    const { t, i18n } = useTranslation();
    const chinese = i18n.language.startsWith('zh');
    function changeLanguage() {
        const language = chinese ? 'en' : 'zh-CN';
        localStorage.setItem('I18N_LANGUAGE', language);
        i18n.changeLanguage(language);
    }
    return (
        <div className={styles.page}>
            <main className={styles.content}>
                <nav className={styles.navigation}>
                    <Link to={checkLogin() ? '/home' : '/login'}>{t('legal.back')}</Link>
                    <button type="button" onClick={changeLanguage}>{chinese ? 'English' : '中文'}</button>
                </nav>
                <h1>{branding.productName} — {t('legal.title')}</h1>
                <dl className={styles.versions}>
                    <dt>{t('legal.version')}</dt><dd>{branding.productVersion}</dd>
                    <dt>{t('legal.sourceCommit')}</dt><dd>{branding.sourceCommit}{branding.sourceModified ? ' + local changes' : ''}</dd>
                    <dt>{t('legal.upstream')}</dt><dd>Apache Doris {branding.upstream.sourceVersion} · {t('legal.sourceBaseline')}</dd>
                </dl>
                <section>
                    <h2>{t('legal.entity')}</h2>
                    <p>{branding.companyZh}<br />{branding.companyEn}</p>
                    <h2>{t('legal.copyright')}</h2>
                    <p>{t('legal.copyrightBody')}</p>
                    <h2>{t('legal.apache')}</h2>
                    <p>{t('legal.apacheBody')} <a href={branding.upstream.url}>{t('legal.upstreamSource')}</a></p>
                    <h2>{t('legal.trademarks')}</h2>
                    <p>{t('legal.trademarksBody')}</p>
                </section>
                <section>
                    <h2>{t('legal.runtimeLibrary')}</h2>
                    <p>{branding.mariadb.name} {branding.mariadb.version} — {branding.mariadb.license}</p>
                    {branding.mariadb.copyrights.map(notice => <div key={notice}>{notice}</div>)}
                    <p>{t('legal.libraryBody')}</p>
                    <NoticeReader file="licenses/LICENSE-LGPL.txt" label={t('legal.lgpl')} />
                </section>
                <section>
                    <h2>{t('legal.materials')}</h2>
                    <p>{t('legal.materialsBody')}</p>
                    <NoticeReader file="LICENSE.txt" label={t('legal.licenses')} />
                    <NoticeReader file="NOTICE.txt" label={t('legal.attributions')} />
                    <NoticeReader file="THIRD-PARTY-NOTICES.txt" label={t('legal.components')} />
                    <NoticeReader file="SOURCE-ACCESS.txt" label={t('legal.sourceAccess')} />
                </section>
            </main>
            <LegalFooter />
        </div>
    );
}
