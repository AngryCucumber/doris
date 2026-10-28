// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
// Modified for MassDB SQL. See MODIFICATIONS.md for details.

package org.apache.doris.datasource.jdbc.client;

import org.apache.doris.catalog.ArrayType;
import org.apache.doris.catalog.ScalarType;
import org.apache.doris.catalog.Type;
import org.apache.doris.datasource.jdbc.util.JdbcFieldSchema;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.Optional;

public class JdbcMySQLClientTest {

    @Test
    public void testIsDorisCompatibleVersionComment() {
        Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("Apache Doris version 3.1.0"));
        Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("SelectDB Cloud version 4.0.5"));
        Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("VeloDB version 2.1.0"));
        Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment(
                "enterprise version enterprise-4.0.5-rc01-0724569463d (Cloud Mode)"));

        Assert.assertFalse(JdbcMySQLClient.isDorisCompatibleVersionComment("MySQL Community Server - GPL"));
        Assert.assertFalse(JdbcMySQLClient.isDorisCompatibleVersionComment(""));
        Assert.assertFalse(JdbcMySQLClient.isDorisCompatibleVersionComment(null));
    }

    @Test
    public void testMassDbDetectionIsIndependentOfDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("massdb-2.0.5-sql-rc415"));
            Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("MASSDB SQL 2.0.5-rc415"));
            Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("APACHE DORIS 4.1.5"));
            Assert.assertTrue(JdbcMySQLClient.isDorisCompatibleVersionComment("SelectDB Cloud version 4.1.5"));
            Assert.assertFalse(JdbcMySQLClient.isDorisCompatibleVersionComment("MySQL Community Server - GPL"));
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    public void testDorisTypeTextWithOmittedScaleOrTrailingAttributes() throws Exception {
        JdbcMySQLClient client = dorisClient();
        Assert.assertEquals(ScalarType.createDecimalV3Type(10, 2), dorisType(client, "decimal(10,2)", 38, 9));
        Assert.assertEquals(ScalarType.createDecimalV3Type(10, 0), dorisType(client, "DECIMAL(10)", 38, 9));
        Assert.assertEquals(ScalarType.createDecimalV3Type(12, 3), dorisType(client, "decimal(12, 3) unsigned", 38, 9));
        Assert.assertEquals(ScalarType.createDecimalV3Type(18, 4), dorisType(client, "decimalv3(18,4)", 38, 9));
        Assert.assertEquals(ScalarType.createStringType(), dorisType(client, "decimal(76,6)", 38, 9));
        Assert.assertEquals(ScalarType.createVarcharType(20), dorisType(client, "varchar(20) not null", 30, 0));
        Assert.assertEquals(ScalarType.createCharType(8), dorisType(client, "char(8)", 30, 0));
        Assert.assertEquals(ScalarType.createVarbinaryType(16), dorisType(client, "varbinary(16)", 30, 0));
        Assert.assertEquals(ArrayType.create(ScalarType.createDecimalV3Type(10, 0), true),
                dorisType(client, "array<decimal(10)>", 38, 9));
        Assert.assertEquals(ArrayType.create(ScalarType.createDecimalV3Type(10, 2), true),
                dorisType(client, "ARRAY<DECIMAL(10,2) UNSIGNED>", 38, 9));
        Assert.assertEquals(ArrayType.create(ScalarType.createVarcharType(5), true),
                dorisType(client, "array<varchar(5)>", 30, 0));
    }

    @Test
    public void testMalformedDorisTypeArguments() throws Exception {
        JdbcMySQLClient client = dorisClient();
        // A top-level column falls back to the precision, scale and length in its JDBC metadata.
        Assert.assertEquals(ScalarType.createDecimalV3Type(18, 4), dorisType(client, "decimal(x,2)", 18, 4));
        Assert.assertEquals(ScalarType.createDecimalV3Type(18, 4), dorisType(client, "decimal(10,2", 18, 4));
        Assert.assertEquals(ScalarType.createDecimalV3Type(18, 4), dorisType(client, "decimal(1,2,3)", 18, 4));
        Assert.assertEquals(ScalarType.createVarcharType(30), dorisType(client, "varchar(*)", 30, 0));
        Assert.assertEquals(ScalarType.createCharType(30), dorisType(client, "char(`len`)", 30, 0));
        // An array element must not borrow the metadata of the outer array column.
        Assert.assertEquals(ArrayType.create(Type.UNSUPPORTED, true), dorisType(client, "array<decimal(x,2)>", 18, 4));
        Assert.assertEquals(ArrayType.create(Type.UNSUPPORTED, true), dorisType(client, "array<varchar(*)>", 30, 0));
        Assert.assertEquals(ArrayType.create(Type.UNSUPPORTED, true), dorisType(client, "array<char(-1)>", 30, 0));
    }

    private static JdbcMySQLClient dorisClient() throws Exception {
        // Avoid opening a remote connection: run the real type mapping of a client that detected Doris.
        JdbcMySQLClient client = Mockito.mock(JdbcMySQLClient.class, Mockito.CALLS_REAL_METHODS);
        Field isDoris = JdbcMySQLClient.class.getDeclaredField("isDoris");
        isDoris.setAccessible(true);
        isDoris.set(client, true);
        return client;
    }

    private static Type dorisType(JdbcMySQLClient client, String typeName, int columnSize, int decimalDigits)
            throws Exception {
        JdbcFieldSchema field = new JdbcFieldSchema(Mockito.mock(ResultSet.class));
        field.setDataTypeName(Optional.of(typeName));
        field.setColumnSize(Optional.of(columnSize));
        field.setDecimalDigits(Optional.of(decimalDigits));
        return client.jdbcTypeToDoris(field);
    }
}
