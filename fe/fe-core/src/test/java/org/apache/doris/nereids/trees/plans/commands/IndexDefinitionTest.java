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

package org.apache.doris.nereids.trees.plans.commands;

import org.apache.doris.analysis.ColumnNullableType;
import org.apache.doris.catalog.AggregateType;
import org.apache.doris.catalog.KeysType;
import org.apache.doris.nereids.analyzer.UnboundFunction;
import org.apache.doris.nereids.analyzer.UnboundSlot;
import org.apache.doris.nereids.exceptions.AnalysisException;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.plans.commands.info.ColumnDefinition;
import org.apache.doris.nereids.trees.plans.commands.info.GeneratedColumnDesc;
import org.apache.doris.nereids.trees.plans.commands.info.IndexDefinition;
import org.apache.doris.nereids.types.ArrayType;
import org.apache.doris.nereids.types.BigIntType;
import org.apache.doris.nereids.types.FloatType;
import org.apache.doris.nereids.types.IntegerType;
import org.apache.doris.nereids.types.MapType;
import org.apache.doris.nereids.types.StringType;
import org.apache.doris.nereids.types.StructField;
import org.apache.doris.nereids.types.StructType;
import org.apache.doris.nereids.types.VariantType;
import org.apache.doris.thrift.TInvertedIndexFileStorageFormat;

import com.google.common.collect.Lists;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class IndexDefinitionTest {
    @Test
    void testVariantIndexFormatV1() throws AnalysisException {
        IndexDefinition def = new IndexDefinition("variant_index", false, Lists.newArrayList("col1"), "INVERTED",
                                                  null, "comment");
        try {
            def.checkColumn(new ColumnDefinition("col1", VariantType.INSTANCE, false, AggregateType.NONE, true,
                                                 null, "comment"), KeysType.UNIQUE_KEYS, true, TInvertedIndexFileStorageFormat.V1);
            Assertions.fail("No exception throws.");
        } catch (AnalysisException e) {
            org.junit.jupiter.api.Assertions.assertInstanceOf(
                    org.apache.doris.nereids.exceptions.AnalysisException.class, e);
            Assertions.assertTrue(e.getMessage().contains("not supported in inverted index format V1"));
        }
    }

    void testArrayTypeSupport() throws AnalysisException {
        IndexDefinition def = new IndexDefinition("array_index", false, Lists.newArrayList("col1"),
                "INVERTED", null, "array test");

        // Test array of supported types
        def.checkColumn(new ColumnDefinition("col1",
                ArrayType.of(StringType.INSTANCE), false, AggregateType.NONE, true, null, "comment"),
                KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);

        def.checkColumn(new ColumnDefinition("col1",
                ArrayType.of(IntegerType.INSTANCE), false, AggregateType.NONE, true, null, "comment"),
                KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);

        def.checkColumn(new ColumnDefinition("col1",
                    ArrayType.of(ArrayType.of(StringType.INSTANCE)), false,
                    AggregateType.NONE, true, null, "comment"),
                    KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);

        // Test array of unsupported types
        try {
            // Array<Float>
            def.checkColumn(new ColumnDefinition("col1",
                    ArrayType.of(FloatType.INSTANCE), false,
                    AggregateType.NONE, true, null, "comment"),
                    KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);
            Assertions.fail("No exception throws for unsupported array element type (Float).");
        } catch (AnalysisException e) {
            Assertions.assertTrue(e.getMessage().contains("is not supported in"));
        }

        try {
            // Array<Array<String>>
            def.checkColumn(new ColumnDefinition("col1",
                    ArrayType.of(ArrayType.of(StringType.INSTANCE)), false,
                    AggregateType.NONE, true, null, "comment"),
                    KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);
            Assertions.fail("No exception throws for array of array type.");
        } catch (AnalysisException e) {
            Assertions.assertTrue(e.getMessage().contains("is not supported in"));
        }

        try {
            // Array<Map<String, Int>>
            def.checkColumn(new ColumnDefinition("col1",
                    ArrayType.of(MapType.of(StringType.INSTANCE, IntegerType.INSTANCE)), false,
                    AggregateType.NONE, true, null, "comment"),
                    KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);
            Assertions.fail("No exception throws for array of map type.");
        } catch (AnalysisException e) {
            Assertions.assertTrue(e.getMessage().contains("is not supported in"));
        }

        try {
            // Array<Struct<name:String, age:Int>>
            ArrayList<StructField> fields = new ArrayList<>();
            fields.add(new StructField("name", StringType.INSTANCE, true, null));
            fields.add(new StructField("age", IntegerType.INSTANCE, true, null));
            def.checkColumn(new ColumnDefinition("col1",
                    ArrayType.of(new StructType(fields)), false,
                    AggregateType.NONE, true, null, "comment"),
                    KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V1);
            Assertions.fail("No exception throws for array of struct type.");
        } catch (AnalysisException e) {
            Assertions.assertTrue(e.getMessage().contains("is not supported in"));
        }
    }

    @Test
    void testNgramBFIndex() throws AnalysisException {
        Map<String, String> properties = new HashMap<>();
        properties.put("gram_size", "3");
        properties.put("bf_size", "10000");

        IndexDefinition def = new IndexDefinition("ngram_bf_index", false, Lists.newArrayList("col1"), "NGRAM_BF",
                                                  properties, "comment");
        def.checkColumn(
                new ColumnDefinition("col1", StringType.INSTANCE, false, AggregateType.NONE, true, null, "comment"),
                KeysType.DUP_KEYS, false, null);
    }

    @Test
    void testInvalidNgramBFIndexColumnType() {
        Map<String, String> properties = new HashMap<>();
        properties.put("gram_size", "3");
        properties.put("bf_size", "10000");

        IndexDefinition def = new IndexDefinition("ngram_bf_index", false, Lists.newArrayList("col1"), "NGRAM_BF",
                                                  properties, "comment");
        Assertions.assertThrows(AnalysisException.class, () ->
                def.checkColumn(
                        new ColumnDefinition("col1", IntegerType.INSTANCE, false, AggregateType.NONE, true, null,
                                             "comment"),
                        KeysType.DUP_KEYS, false, null));
    }

    @Test
    void testNgramBFIndexInvalidSize() {
        Map<String, String> properties = new HashMap<>();
        properties.put("gram_size", "256");
        properties.put("bf_size", "10000");

        IndexDefinition def = new IndexDefinition("ngram_bf_index", false, Lists.newArrayList("col1"), "NGRAM_BF",
                                                  properties, "comment");
        Assertions.assertThrows(AnalysisException.class, () ->
                def.checkColumn(new ColumnDefinition("col1", StringType.INSTANCE, false, AggregateType.NONE, true, null,
                                                     "comment"),
                                KeysType.DUP_KEYS, false, null));
    }

    @Test
    void testNgramBFIndexInvalidSize2() {
        Map<String, String> properties = new HashMap<>();
        properties.put("gram_size", "3");
        properties.put("bf_size", "65536");

        IndexDefinition def = new IndexDefinition("ngram_bf_index", false, Lists.newArrayList("col1"), "NGRAM_BF",
                                                  properties, "comment");
        Assertions.assertThrows(AnalysisException.class, () ->
                def.checkColumn(new ColumnDefinition("col1", StringType.INSTANCE, false, AggregateType.NONE, true, null,
                                                     "comment"),
                                KeysType.DUP_KEYS, false, null));
    }

    private ColumnDefinition geoColumn(String name, org.apache.doris.nereids.types.DataType type,
            Expression generatedExpr) {
        java.util.Optional<GeneratedColumnDesc> desc = generatedExpr == null
                ? java.util.Optional.empty()
                : java.util.Optional.of(new GeneratedColumnDesc("gen", generatedExpr));
        return new ColumnDefinition(name, type, false, null, ColumnNullableType.NULLABLE, -1,
                java.util.Optional.empty(), java.util.Optional.empty(), "comment", desc);
    }

    @Test
    void testGeoIndex() {
        Expression s2Expr = new UnboundFunction("st_s2_cellid",
                Lists.newArrayList(new UnboundSlot("lon"), new UnboundSlot("lat")));

        // valid: BIGINT generated st_s2_cellid column on DUP table; lng/lat column names
        // must be recorded into the index properties for the BE to match predicates.
        IndexDefinition def = new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"),
                "GEO", new HashMap<>(), "geo test");
        def.checkColumn(geoColumn("__s2", BigIntType.INSTANCE, s2Expr),
                KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V2);
        Assertions.assertEquals("lon", def.getProperties().get("lng_column"));
        Assertions.assertEquals("lat", def.getProperties().get("lat_column"));

        // valid: UNIQUE MOW
        new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO", new HashMap<>(),
                "geo test").checkColumn(geoColumn("__s2", BigIntType.INSTANCE, s2Expr),
                KeysType.UNIQUE_KEYS, true, TInvertedIndexFileStorageFormat.V2);

        // invalid: UNIQUE without MOW / AGG
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        new HashMap<>(), "geo test").checkColumn(
                        geoColumn("__s2", BigIntType.INSTANCE, s2Expr),
                        KeysType.UNIQUE_KEYS, false, TInvertedIndexFileStorageFormat.V2));
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        new HashMap<>(), "geo test").checkColumn(
                        geoColumn("__s2", BigIntType.INSTANCE, s2Expr),
                        KeysType.AGG_KEYS, false, TInvertedIndexFileStorageFormat.V2));

        // invalid: not BIGINT
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        new HashMap<>(), "geo test").checkColumn(
                        geoColumn("__s2", IntegerType.INSTANCE, s2Expr),
                        KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V2));

        // invalid: plain (non-generated) BIGINT column
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        new HashMap<>(), "geo test").checkColumn(
                        geoColumn("__s2", BigIntType.INSTANCE, null),
                        KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V2));

        // invalid: generated from a different function
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        new HashMap<>(), "geo test").checkColumn(
                        geoColumn("__s2", BigIntType.INSTANCE, new UnboundFunction("abs",
                                Lists.newArrayList((Expression) new UnboundSlot("lon")))),
                        KeysType.DUP_KEYS, false, TInvertedIndexFileStorageFormat.V2));

        // invalid property
        Map<String, String> badProps = new HashMap<>();
        badProps.put("leaf_rows", "not_a_number");
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        badProps, "geo test").validate());
        Map<String, String> unknownProps = new HashMap<>();
        unknownProps.put("no_such_prop", "1");
        Assertions.assertThrows(AnalysisException.class, () ->
                new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO",
                        unknownProps, "geo test").validate());
        Map<String, String> goodProps = new HashMap<>();
        goodProps.put("leaf_rows", "8192");
        new IndexDefinition("idx_geo", false, Lists.newArrayList("__s2"), "GEO", goodProps,
                "geo test").validate();
    }
}
