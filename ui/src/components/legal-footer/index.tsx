// MassDB SQL implementation.
// Licensing decision pending (A02); see dist/source-headers.json.
// This file does not assert an ASF contributor agreement.
import React from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { branding } from 'Src/constants/branding';
import { getBasePath } from 'Src/utils/utils';
import styles from './index.less';

export default function LegalFooter({ appearance = 'default' }: { appearance?: 'default' | 'transparent' }) {
    const { t, i18n } = useTranslation();
    const company = i18n.language.startsWith('zh') ? branding.companyZh : branding.companyEn;
    return (
        <footer className={[styles.footer, appearance === 'transparent' ? styles.transparent : ''].join(' ')}>
            {branding.companyCopyrightConfirmed && <div>© {branding.copyrightYears} {company}</div>}
            <div>{branding.productName}
                {branding.companyCopyrightConfirmed && <> · {t('legal.scope')}</>}
                {' · '}<Link to="/legal-notices">{t('legal.title')}</Link>
            </div>
            <div className={styles.library}>
                <div>{branding.mariadb.name} · {branding.mariadb.license}</div>
                {branding.mariadb.copyrights.map(notice => <div key={notice}>{notice}</div>)}
                <a href={`${getBasePath()}/legal/licenses/LICENSE-LGPL.txt`}>{t('legal.lgpl')}</a>
            </div>
        </footer>
    );
}
