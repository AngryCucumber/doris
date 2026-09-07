// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.
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
