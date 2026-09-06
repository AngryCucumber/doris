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

import React from 'react';
import { Route, Redirect, Switch } from 'react-router-dom';
import { checkLogin } from 'Src/utils/utils';

const renderRoutes = (routes, authPath = '/login') => {
    if (routes) {
        return (
            <Switch>
                {routes.map((route, i) => (
                    <Route
                        key={route.key || i}
                        path={route.path}
                        exact={route.exact}
                        strict={route.strict}
                        render={(props) => {
                            if (!route.public && !checkLogin()) {
                                return <Redirect to={authPath} />;
                            }
                            if (props.location.pathname === '/') {
                                return <Redirect to={'/home'} />;
                            }
                            return route.render ? (
                                route.render({ ...props, route: route })
                            ) : (
                                <route.component {...props} route={route} />
                            );
                        }}
                    />
                ))}
            </Switch>
        );
    }
    return null;
};

export default renderRoutes;
