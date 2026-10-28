// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.jdbc.massdb;

import org.apache.doris.common.jni.vec.ColumnType;
import org.apache.doris.jdbc.MySQLJdbcExecutor;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class MySQLJdbcArrayTest {
    private List<?> decode(String json, String elementType) throws Exception {
        MySQLJdbcExecutor executor = Mockito.mock(MySQLJdbcExecutor.class, Mockito.CALLS_REAL_METHODS);
        Method method = MySQLJdbcExecutor.class.getDeclaredMethod("convertArray", Object.class, ColumnType.class);
        method.setAccessible(true);
        return (List<?>) method.invoke(executor, json, ColumnType.parseType("element", elementType));
    }

    @Test
    void preservesLargeIntegersAndNestedNulls() throws Exception {
        BigInteger large = new BigInteger("9007199254740993");
        BigInteger largest = new BigInteger("170141183460469231731687303715884105727");
        Assertions.assertEquals(Arrays.asList(large, largest, null),
                decode("[9007199254740993,170141183460469231731687303715884105727,null]", "largeint"));
        Assertions.assertEquals(Arrays.asList(Arrays.asList(large, null), null, Collections.emptyList()),
                decode("[[9007199254740993,null],null,[]]", "array<largeint>"));
    }

    @Test
    void preservesDecimalsAndSignedZero() throws Exception {
        Assertions.assertEquals(Arrays.asList(new BigDecimal("12345678901234567890.123456"), null),
                decode("[12345678901234567890.123456,null]", "decimalv3(30,6)"));
        List<?> floats = decode("[-0.0,0.0,null]", "float");
        Assertions.assertEquals(Float.floatToRawIntBits(-0.0f), Float.floatToRawIntBits((Float) floats.get(0)));
        Assertions.assertEquals(Float.floatToRawIntBits(0.0f), Float.floatToRawIntBits((Float) floats.get(1)));
        Assertions.assertNull(floats.get(2));
    }

    @Test
    void preservesNullsAndTimestampFractions() throws Exception {
        Assertions.assertEquals(Arrays.asList(true, false, null), decode("[true,0,null]", "boolean"));
        Assertions.assertEquals(Arrays.asList(LocalDate.of(2026, 10, 28), null),
                decode("[\"2026-10-28\",null]", "datev2"));
        for (int precision = 0; precision <= 6; precision++) {
            String fraction = "123456".substring(0, precision);
            String value = "2026-10-28 12:34:56" + (precision == 0 ? "" : "." + fraction);
            LocalDateTime expected = LocalDateTime.parse(value.replace(' ', 'T'));
            Assertions.assertEquals(Arrays.asList(expected, null),
                    decode("[\"" + value + "\",null]", "datetimev2(" + precision + ")"));
        }
    }
}
