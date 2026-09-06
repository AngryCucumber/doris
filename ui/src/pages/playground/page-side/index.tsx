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

import React, {SyntheticEvent, useState} from 'react';
import {Resizable} from 'react-resizable';
import styles from './index.less';

require('react-resizable/css/styles.css');

export function PageSide(props: any) {
    const {children} = props;
    const [sideBoxWidth, setSideBoxWidth] = useState(300);

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
            minConstraints={[220, 0]}
            maxConstraints={[480, Infinity]}
            axis="x"
        >
            <aside className={styles.side} style={{width: sideBoxWidth}}>
                {children}
            </aside>
        </Resizable>
    );
}
 
