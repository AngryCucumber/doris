/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
// Modified for MassDB SQL. See MODIFICATIONS.md for details.

import React, {SyntheticEvent, useEffect, useRef, useState} from 'react';
import {Resizable} from 'react-resizable';
import styles from './index.less';

require('react-resizable/css/styles.css');

const MIN_WIDTH = 220;
const MAX_WIDTH = 480;
const MAX_SHARE = 0.4;

export function PageSide(props: any) {
    const {children} = props;
    const side = useRef<HTMLElement>(null);
    const [sideBoxWidth, setSideBoxWidth] = useState(300);
    const [maxWidth, setMaxWidth] = useState(MAX_WIDTH);

    // The only upper limit: 480 px or 40% of the Playground row, whichever is smaller. A second limit in the
    // stylesheet let the width grow past what was drawn, so dragging back did nothing until it caught up.
    useEffect(() => {
        const row = side.current && side.current.parentElement;
        if (!row) return undefined;
        const update = () => {
            const style = getComputedStyle(row);
            const content = row.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
            const limit = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Math.floor(content * MAX_SHARE)));
            setMaxWidth(limit);
            setSideBoxWidth(width => Math.min(width, limit));
        };
        update();
        const Observer = (window as any).ResizeObserver;
        if (Observer) {
            const observer = new Observer(update);
            observer.observe(row);
            return () => observer.disconnect();
        }
        window.addEventListener('resize', update);
        return () => window.removeEventListener('resize', update);
    }, []);

    const onResize = function (e: SyntheticEvent, data: any) {
        const width = data.size.width || 300;
        setSideBoxWidth(width);
    };
    return (
        <Resizable
            width={sideBoxWidth}
            height={0}
            resizeHandles={['e']}
            onResize={onResize}
            minConstraints={[MIN_WIDTH, 0]}
            maxConstraints={[maxWidth, Infinity]}
            axis="x"
        >
            <aside ref={side} className={styles.side} style={{width: sideBoxWidth}}>
                {children}
            </aside>
        </Resizable>
    );
}
 
