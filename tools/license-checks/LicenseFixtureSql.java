// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/** JDBC oracle for the explicitly owned isolated P0 fixture; never logs credentials. */
public final class LicenseFixtureSql {
    private LicenseFixtureSql() {
    }

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode config = mapper.readTree(new File(args[0]));
        Properties properties = new Properties();
        properties.setProperty("user", config.path("user").asText("root"));
        properties.setProperty("password", System.getenv().getOrDefault(
                config.path("password_env").asText(), ""));
        properties.setProperty("connectTimeout", "10000");
        properties.setProperty("socketTimeout", "60000");
        String url = "jdbc:mariadb://127.0.0.1:" + config.path("query_port").asInt() + "/";
        ObjectNode report = mapper.createObjectNode();
        ArrayNode statements = report.putArray("statements");
        boolean continueOnError = config.path("continue_on_error").asBoolean(false);
        boolean failed = false;
        try (Connection connection = DriverManager.getConnection(url, properties);
                Statement statement = connection.createStatement()) {
            report.put("driver", connection.getMetaData().getDriverVersion());
            for (JsonNode item : config.path("sql")) {
                String sql = item.asText();
                ObjectNode result = statements.addObject().put("sql", sql);
                long started = System.nanoTime();
                try {
                    if (statement.execute(sql)) {
                        ArrayNode rows = result.putArray("rows");
                        ArrayNode columns = result.putArray("columns");
                        try (ResultSet values = statement.getResultSet()) {
                            for (int column = 1; column <= values.getMetaData().getColumnCount(); column++) {
                                columns.addObject().put("name", values.getMetaData().getColumnLabel(column))
                                        .put("type", values.getMetaData().getColumnTypeName(column));
                            }
                            while (values.next()) {
                                if (rows.size() >= 10000) {
                                    throw new IllegalStateException("Fixture oracle exceeded its result bound");
                                }
                                ObjectNode row = rows.addObject();
                                for (int column = 1; column <= values.getMetaData().getColumnCount(); column++) {
                                    row.put(values.getMetaData().getColumnLabel(column), values.getString(column));
                                }
                            }
                        }
                    } else {
                        result.put("update_count", statement.getUpdateCount());
                    }
                    result.put("success", true);
                } catch (SQLException error) {
                    failed = true;
                    result.put("success", false);
                    result.put("error_code", error.getErrorCode());
                    result.put("sql_state", error.getSQLState());
                    result.put("error_message", error.getMessage());
                } finally {
                    result.put("elapsed_nanos", System.nanoTime() - started);
                }
                if (failed && !continueOnError) {
                    report.put("stopped_on_error", true);
                    break;
                }
            }
        } catch (SQLException error) {
            failed = true;
            report.put("connection_error", true);
            report.put("error_code", error.getErrorCode());
            report.put("sql_state", error.getSQLState());
            // JDBC connection exceptions can embed properties; never archive their message.
        }
        report.put("success", !failed);
        System.out.println(mapper.writeValueAsString(report));
        if (failed && (!continueOnError || report.path("connection_error").asBoolean())) {
            System.exit(2);
        }
    }
}
