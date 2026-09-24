<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 原版 UI 实际并发功能窗口

2026-09-24：新增独立 controller/driver；真实执行范围与失败记录见文末，不能从代码存在推定通过。
既有 `ui_baseline_fixture.py` / `LicenseUiBaselineFixture.cjs` 及其已冻结18格导航计划不变。
离线测试及真实运行状态必须分别记录；新增代码本身不构成并发通过。

用户已确认页面和业务背景的指标口径分开。权威输入仍为
[性能清单](/data/project/massdb-sql/docs/license-performance-cases-20260922.json)中的
`measurement_policy.ui_measurement_contract` 与 LP021/022 `metric_scope`。
本工具每个新计划冻结完整规范摘要及该明确决策内容；不写全局规范或旧计划。
页面保留300秒窗口、10秒刷新、实际1/10/50并发、请求数、原始延迟和资源；
页面样本不足时P99为null且不声称达标。持续查询/写入的原样本量、1%吞吐/CPU、
2%P95/P99、独立A/A窗口与置信要求保持不变。本工具不提供业务A/A统计资格。

## 执行范围与真实并发

`ui_concurrent_fixture.py` 默认只创建新计划。单 FE 保留3前缀×2语言×3身份×1/10/50
共54个窗口；三 FE 保留每个FE入口×3前缀×2语言×3身份×1/10共108个窗口。
各窗口独立执行，每窗只有一个固定身份/语言/前缀，但其声明数量的真实 browser context
同时存在于同一 Chromium，Cookie/localStorage 各自隔离。第一个context使用本次私有profile，
其他context独立创建；所有句柄一取得就计入清理所有权。

所有context分别真实登录、核验原版Home及权限行为，全部ready后才释放共同单调时钟epoch。
固定计划仍为第10至290秒共29次刷新，第95/195秒两次额外导航。单个context的慢操作保留
原到达时间及排队时延，不重排后续计划；失败会停止其page并保留剩余未发送事件，其他context
继续原完整窗口。任何失败均保留FAIL，不把剩余context当成较小并发成功。最后操作较早结束
仍须维持完整300秒。Python独立核对各context的准备、共同epoch、窗口结束、31个操作、
唯一真实HTTP请求、JSON业务/拒绝码、页面oracle和清理回执；不只相信driver的并发布尔标记。

每context使用一个既有透明代理，固定指向同一被测FE。这样保留每proxy的16连接界限，
避免把一个16连接proxy放到50个context前制造非FE的503瓶颈。代理不改响应体、不注入Basic
或查询header，额外CPU/线程/RSS计入客户端观测。浏览器阻止外部网络。全局RSS/CPU affinity、
窗口/整轮deadline及文件大小有界。私有profile、进程和每个proxy均独立清理；配置仅经有界、
有deadline的stdin传入，凭据不会进入argv、报告或原始headers。

Home、Playground、Configuration分别核验真实API及页面。非管理员原权限拒绝单独记录，
不计成功业务操作。深链接、结果完整三行、history、语言切换及注销菜单仍由已有18格导航fixture
先验证；新并发窗口不把未执行的导航动作写成通过。无需再为同一需求额外运行18×300秒纯导航：
已冻结18格可达导航之后，可直接运行这里的刷新加可选背景窗口。

## 可选的一份共享业务背景

plan和probe都必须显式指定同一个 `--background` 输入，格式沿用
[背景规格第10节](/data/project/massdb-sql/tools/license-checks/ui-baseline-fixture.md:199)。
每窗口只有一个背景JVM及本次独立目标表，不能因context数量变为10/50而把业务流成倍复制。
百万行源数据计时前后完整验证，固定读键/开环到达、写入ACK/未知、可见性与完整目标模型、
表归属和清理保持原工具的要求。所有context ready后，driver仅提交一份background ready，
再依据真实Java窗口回执释放UI；Java与Node单调时钟原点分开，通过各自UTC锚点关联。
背景报告保存该次真实token、第一项实际页面动作的UTC时间以及读到背景结束回执后仍持有全部
context的UTC时间，直接供既有Python背景消费者核验。浏览器进程、profile或任一proxy清理未知
时，即使背景已清理也停止后续矩阵；剩余窗口保留为未执行。

现有背景helper仍是明确的300秒功能输入，不是正式业务A/A执行器。即使功能共存通过，
`business_background_precision_qualified=false`、`AA_qualified=false`、完整LP021/022/P0均不能标通过。
业务正式窗口、速率/稳定性冻结、样本量、完整资源及统计仍按权威清单另验。

## 背景进程的启动身份

背景JVM与javac启动后，先按本次直接启动参数绑定exe、NUL结尾argv摘要、PID和网络namespace。
初次/proc命令读取为空或不完整时，最多在250ms与既有阶段绝对期限中较早的边界内重读；
连续两次完整匹配后才保存有效pin。任何已观察到的非空错误命令、exe、namespace或寿命变化
立即失败，冻结后的身份校验仍保持严格。分次/proc读取不能证明原子快照或连续无exec。

Popen先登记；取得有效pin后先保留所有权再写证据；早退保留真实parent wait和退出码。
编译120秒、背景准备及恢复清理阶段的期限均在launch前固定，启动身份等待不能延长原期限。
2026-09-24合并版48项Python检查通过；同源精确JDK的javac、普通启动、显式注入一次空读
和真实早退四个生命周期案例通过。actual-v3第三窗失败及清理记录保留，这些离线/短测证据
不替代尚未完成的50context或54窗实际验证。

## 后续命令

环境释放后，先复核当前cluster身份与已有18格导航的覆盖记录；不重复已满足的导航矩阵。下列目录须重新准备，
账号必须已有准确grants且凭据由受控环境提供；工具不创建账号或修改认证配置。

```bash
python3 tools/license-checks/ui_concurrent_fixture.py \
  --cluster-record .build-records/license-p0-p1-20260924/baseline-jdk1704-be4g-functional-20260924-v1/cluster.json \
  --accounts .build-records/license-p0-p1-20260924/ui-original-prerequisites-v1/ui-accounts.json \
  --node /data/project/massdb-sql/.build-records/toolchains/node-v22.23.2-linux-arm64/bin/node \
  --chromium /root/.cache/ms-playwright/chromium-1243/chrome-linux-arm64/chrome \
  --cpus 0,1,2,3,4 --rss-limit-mib 6144 --reserve-mib 2048 \
  --allow-no-browser-sandbox --cell-timeout-seconds 600 --whole-timeout-seconds 86400 \
  --background .build-records/license-p0-p1-20260924/ui-original-prerequisites-v1/ui-background.json \
  --output .build-records/license-p0-p1-20260924/lp021-ui-concurrent-next-owned

# 仅在重新核对的owned private namespace中执行；该background输入必须已实际准备。
python3 tools/license-checks/ui_concurrent_fixture.py --mode probe \
  --plan .build-records/license-p0-p1-20260924/lp021-ui-concurrent-next-owned/plan.json \
  --background .build-records/license-p0-p1-20260924/ui-original-prerequisites-v1/ui-background.json
```

无背景诊断须在plan/probe两处都省略 `--background`，结果明确没有持续业务共存证据。
LP022原版前提用 `--cluster-plan` 代替 `--cluster-record`，不能混用。全部单FE窗口计时下界4.5小时，
三FE下界9小时，另加登录、源模型、预检和清理；这些数字不包含正式业务A/A。
不能将RSS预算当作已验证的50context内存需求；启动前实际可用内存不足会拒绝。

每格保存 `browser.json`、`controller.json`、1秒采样的 `resources.jsonl`，以及选择背景时其完整既有证据。
资源记录分开保存controller/proxy、Node/Chromium、背景JVM、FE和BE的CPU/RSS/IO。
GC分配/暂停、既有RPC和独立进程网络仍未提供，短命进程或采样间峰值可能缺失，不能声称完整CPU归因或正式资源精度。
报告实时保留全部完成和未执行窗口；FAIL、未知清理和输入漂移不会自动重试或重用旧计划。

计划阶段可显式提供 `--stop-on-failed-window`。默认保持原行为：功能FAIL但清理完整时继续矩阵。
启用后该布尔选项写入plan，probe只能沿用冻结值；当前窗口先完成背景finish、保存完整回执、
核验浏览器/代理/profile及背景清理和源码绑定，再因功能FAIL停止，下一窗不会启动。
完整54/108格计划保持不变，report记录 `FAILED_WINDOW_POLICY` 与全部 `windows_not_executed`。
物理清理未知始终优先停止并记录 `WINDOW_CLEANUP_UNCONFIRMED`，不能当作正常功能停止。

离线定向命令（不启动浏览器）：

```bash
MASSDB_UI_TEST_NODE=/data/project/massdb-sql/.build-records/toolchains/node-v22.23.2-linux-arm64/bin/node \
  taskset -c 5 python3 -B -m unittest discover -s tools/license-checks -p test_ui_concurrent_fixture.py -v
taskset -c 5 .build-records/toolchains/node-v22.23.2-linux-arm64/bin/node --test tools/license-checks/ui-concurrent-oracles.test.cjs
```

Python跨语言接口用例只加载JS纯函数生成背景回执，再调用真实Python消费者；不加载Playwright，
不访问FE/BE。显式提供测试Node路径，避免该项因宿主机PATH中没有Node而跳过。

2026-09-24原版18格已在 `lp021-ui-navigation-actual-v2` 实际执行：6 PASS、12 PARTIAL。
18格规定的导航、对象权限、三行查询（有权限账号）及真实注销均通过；12个PARTIAL只保留额外的
新页面查询结果深链依赖history.state限制。原始状态与exit2不覆盖，范围审计在
`required-navigation-audit.json`；这不代表本工具54个并发窗口、300秒背景或正式A/A已通过。

原版并发首轮 `lp021-ui-concurrent-actual-v1` 为 FAIL / exit 2：1与10 context的两个300秒窗口通过，
第3格在后台javac准备阶段失败，50 context尚未创建，其余51格未执行。原始首因仅存ValueError，
编译器stderr未归档，不能将匹配的class字节或当前进程缺席当作历史exit 0。外层与独立清理已确认
原服务不变、账号/临时表/私有profile/owned进程缺席，原内层cleanup=false仍保留。

后台生命周期修复只处理进程退出过渡：用前后start ticks夹住身份读取；缺字段、空cmdline或退出状态
最多等待250毫秒，并受原绝对deadline限制，必须获得Popen真实wait回执。已观测到不同start ticks、
namespace、exe或非空命令摘要时立即失败，未退出超时亦失败；不重新认领进程、不向未知身份发信号。
退出中的不完整资源样本丢弃，并写入rss=null的原因记录，不补零或补造exit 0。每个背景目录保存
`process-lifecycle.json`中的安全stage/reason、身份差异和真实exit；首个后台失败也保留在窗口报告，
后续reap或诊断落盘异常不会抹去首错。仍不保存子进程原始stdout/stderr、命令行或环境凭据。
修改后的源码必须重新冻结到新计划/配置及新输出目录，不能继续首轮旧计划，不能自动重试失败窗口。


## 固定四路准备与同次RSS超限证据

新计划冻结 `preparation_concurrency=4`，仅限制准备阶段的页面创建、真实登录和Home
核验。已创建的全部1/10/50 BrowserContext始终保留，全部ready后才释放原共同epoch；计时阶段
所有context的31次动作、300秒、10秒节奏和并行循环不变。原后台Java的90秒release截止未改，
Node另从自身启动设置90秒上限，各准备批次不能重置期限。内存仍按原6GiB的进程RSS和判断，
不是PSS；不能承诺此变更能使50个常驻页面通过内存限制。

`preparation.json`只包含固定结构的阶段、实际created/ready/inflight/maximum和最多50项结果，
每次原子替换且最大64KiB，不含账号秘密、Cookie或完整网络报文。进程在浏览器启动或准备中
被终止时，已发布计数可独立保留。Python同时核验最终完整数量及最大四路准备。

RSS保护每次只取得一份带起止时间的进程观测，PID/lifetime去重；记录每进程RSS、角色和未取得
值的null。该份观测既用于计算总和也用于判定超限；超限时原样写`resource-limit.json`和窗口
固定reason，禁止事后再采一份冒充crossing。正常1秒资源帧另包含当时使用的RSS guard观测。
共有页仍可能重复计入不同进程的RSS；逐进程采集不是同时原子快照，不可声称PSS或完整物理内存。

准备或deadline首错优先保留；最后回执失写作为独立secondary错误，不覆盖原始失败。
对应35项Python、21项Node离线检查已在CPU5全部通过，无跳过；旧五份源码先独立快照后才提升。
命令、原始日志、退出码及新旧摘要见
[提升验证回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-bounded-preparation-draft-v1/validation-v1/promotion-receipt.json)。
这些测试使用纯函数/虚拟时间/定向替身，不启动浏览器、JVM或SQL/HTTP，不能替代真实资源窗口。

原版第二轮 `lp021-ui-concurrent-actual-v2` 仍为FAIL / exit2：1与10 context的两个300秒窗口通过；
第3格在准备中观测RSS 7684.0546875 MiB，超过原6144 MiB限制，50context未到ready且准确created数未知；
后51格未执行。该轮已经清理并保留原始失败，不能将此工具修复或先前两格升级为完整54窗通过。
四路准备后的真实窗口尚未执行；必须新配置/计划/输出、重新绑定源码并另行移交实际环境。
