<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# GC 日志记录时间映射

`gc_window_mapping.py` 提供纯函数 `parse_pause_line(bytes)` 和
`map_archive(archive_bytes, observer_gc_summary, frozen_context)`。
28项离线测试已通过；当前没有接入采集器、修改FE日志配置或执行真实GC窗口验收。

解析器支持原GC Pause日志增加 `timenanos` 后的记录时间。当前只接受已由本地源码/二进制证据确认的
Temurin17.0.4+8，其精确libjvm摘要与时间语义标识固定在模块中。`timenanos` 是日志记录构造时刻，
不保证是STW开始、结束或落盘时刻。映射按实际单调时钟窗口 `[start_ns,end_ns)` 分配整条记录，
保留日志中的暂停时长，不由“记录时间减时长”构造暂停起点，也不将毫秒文本转换后的整数冒称纳秒准确度。

输入保留现有observer的逐事件JSONL、原行摘要、文件device/inode/generation及字节区间、FE PID/start ticks、
read batch、confirmed cursor和terminal prefix。调用方还须提供实际采集的boot ID、time namespace及offset文件摘要，
源进程/工作负载前后绑定和真实窗口边界。函数检查这些输入的一致性，无法替外部调用方证明字典是如何采集的。
真正运行时必须由有明确归属的controller冻结原始证据、配置、源码及现场身份。

日志选择、路径和轮转必须精确保持 `gc*,classhisto*=trace`、10份50M轮转，只新增
`time,uptime,timenanos` 装饰器。FE进程/命令/网络namespace、正PID/start ticks及规范绝对路径均须完整匹配。
现有两装饰器日志返回空monotonic字段，不能映射，也不回填历史结果。

任一丢失、未确认写入、残缺行、文件代次缺失、重复/重叠偏移、时间域不一致或清理错误，都会返回
`UNQUALIFIED`，不输出达标窗口汇总。终态读到的事件单独标为 `terminal_drain`，但其窗口仍由原记录时间决定。
同GC ID的Remark/Cleanup分别保留。零事件只表示已确认前缀中没有事件；
`all_jvm_gc_pauses_proven` 和 `complete_stw_window_distribution_proven` 始终为false。

当前collector会丢弃已完全读完且unlink的历史generation cursor；因此这类generation若仍有归档事件，
映射器会拒绝缺少来源证明的输入。下一collector版本须保存有界的退休cursor/segment证明，再支持该轮转场景，
不能直接绕过校验。当前运行配置和observer尚未修改；正式接线必须新冻结同配置A/A，不改历史回执。

输入上限为32MiB事件归档、100,000条事件、每行64KiB、12个cursor和10,000个窗口。窗口分配使用二分查找。
这些是工具内存/输入界限，不是FE性能通过记录；实际收集成本和日志配置影响仍需测量。

离线测试：

```bash
python3 -B -m unittest discover -s tools/license-checks -p test_gc_window_mapping.py -v
```

测试覆盖半开边界、drain分类、旧日志拒绝、身份/时钟/日志选择不符、丢失/轮转/写入确认、
同ID多暂停、畸形输入和零事件范围；不启动JVM或服务、不主动触发GC。
