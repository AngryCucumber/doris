#!/usr/bin/env python3
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

"""Summarize one offline JDK 17 Thread.print -l dump, without inferring lock owners.

Exit codes: 0 = summary or lock matches; 1 = no lock matches; 2 = invalid input.
Only the supplied text file is read. No JVM attach, network, or file writes occur.
"""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys


HEADER = re.compile(r'^"(?P<name>.*)"\s+.*\btid=0x[0-9a-f]+\b.*\bnid=0x[0-9a-f]+\b', re.I)
STATE = re.compile(r'^\s+java\.lang\.Thread\.State:\s+(\w+)')
FRAME = re.compile(r'^\s+at\s+(.+?)\s*$')
ADDRESS = re.compile(r'(?<![\w])0x[0-9a-f]+(?![\w])', re.I)
NO_STATE = "NO_JAVA_STATE"
FOCUS = (
    ("EditLog-Flusher", re.compile(r'EditLog-Flusher', re.I)),
    ("timePrinter / logTimestamp", re.compile(r'timePrinter|logTimestamp', re.I)),
    ("事务路径（匹配不代表持锁）", re.compile(r'DatabaseTransactionMgr|GlobalTransactionMgr|TransactionState')),
    ("BDB / JE", re.compile(r'BDBJE|BDBEnvironment|com\.sleepycat\.je\.|\bJE ', re.I)),
    ("MetricRepo", re.compile(r'MetricRepo')),
    ("AsyncLogger / Disruptor", re.compile(r'AsyncLogger|AsyncAppender|disruptor', re.I)),
    ("发布线程", re.compile(r'PUBLISH_VERSION|PublishVersionDaemon', re.I)),
    ("Thrift", re.compile(r'thrift-server-pool|TThreadPoolServer|org\.apache\.thrift', re.I)),
)


@dataclass
class ThreadBlock:
    name: str
    line: int
    state: str
    frames: tuple
    raw: str


def bounded_integer(low, high):
    def parse(value):
        try:
            result = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("必须是整数") from None
        if not low <= result <= high:
            raise argparse.ArgumentTypeError(f"必须在 {low} 到 {high} 之间")
        return result
    return parse


def lock_address(value):
    if not re.fullmatch(r'0x[0-9a-f]+', value, re.I):
        raise argparse.ArgumentTypeError("锁地址必须为 0x 开头的十六进制数")
    return int(value, 16)


def parse_dump(stream, keep_raw=False):
    blocks = []
    warnings = []
    current = None
    lines = []
    dump_headers = 0
    unknown_headers = []
    footer_seen = False
    has_text = False
    replacements = 0

    def finish():
        if current is None:
            return
        states = [match.group(1) for line in lines if (match := STATE.match(line))]
        frames = tuple(match.group(1) for line in lines if (match := FRAME.match(line)))
        blocks.append(ThreadBlock(current[0], current[1], states[0] if states else NO_STATE,
                                  frames, "".join(lines) if keep_raw else ""))

    for number, line in enumerate(stream, 1):
        has_text = has_text or bool(line.strip())
        replacements += line.count("\ufffd")
        if line.startswith("Full thread dump"):
            dump_headers += 1
            if dump_headers > 1:
                raise ValueError("检测到多个 dump；请每次只输入一个快照，锁地址不能跨快照关联")
        if line.startswith("JNI global ref") or re.match(r'^Found .*Java-level deadlock', line):
            finish()
            current, lines = None, []
            footer_seen = True
            continue
        if footer_seen:
            continue
        match = HEADER.match(line)
        if match:
            finish()
            current, lines = (match.group("name"), number), [line]
        elif line.startswith('"'):
            # Do not attach an unsupported thread/deadlock header to its predecessor.
            finish()
            current, lines = None, []
            unknown_headers.append(number)
        elif current is not None:
            lines.append(line)
    finish()
    if not has_text:
        raise ValueError("输入为空或仅含空白")
    if not blocks:
        raise ValueError("未识别到 JDK 17 线程头（需要引号线程名、tid 和 nid）")
    if dump_headers == 0:
        warnings.append("缺少 Full thread dump 标记；可能是片段，计数仅代表已识别内容")
    if not footer_seen:
        warnings.append("未见 dump 尾部标记；文件可能被截断，末尾线程块也可能不完整")
    if unknown_headers:
        sample = ", ".join(str(number) for number in unknown_headers[:3])
        warnings.append(f"跳过 {len(unknown_headers)} 个未知引号头；示例行号：{sample}")
    if replacements:
        warnings.append(f"出现 {replacements} 个 Unicode 替换字符；原始编码/损坏可能影响匹配")
    return blocks, warnings


def names(blocks):
    return ", ".join(json.dumps(block.name, ensure_ascii=False) + f" (L{block.line})"
                     for block in blocks[:2])


def print_limits(warnings):
    print("范围：仅分析本文件中识别到的线程；不连接进程、不推断唯一锁 owner。")
    print("限制：未知头格式/截断会漏计；单份栈不能证明长期阻塞或 CPU 忙。")
    print("锁地址只在同一快照内关联；Object.wait 中的 locked 不证明仍持有该 monitor；")
    print("RRWL 读锁 owner、StampedLock owner 通常不能从此文本完整确定。")
    for warning in warnings:
        print(f"警告：{warning}")


def print_summary(blocks, top, frame_count):
    print(f"\n已识别线程块：{len(blocks)}")
    print("线程状态计数（无 java.lang.Thread.State 的 JVM/native 线程单列）：")
    for state, count in Counter(block.state for block in blocks).most_common():
        print(f"  {state}: {count}")

    groups = defaultdict(list)
    for block in blocks:
        groups[(block.state, block.frames)].append(block)
    ordered = sorted(groups.items(), key=lambda item: (-len(item[1]), item[1][0].line))
    selected = ordered[:top]
    print(f"\nTop stack 分组：显示 {len(selected)}/{len(groups)} 组；按状态+完整栈帧精确分组，忽略锁地址。")
    print(f"每组最多 2 个名字、{frame_count} 个显示帧；不同底层调用链不会因顶帧相同而合并。")
    for index, ((state, frames), members) in enumerate(selected, 1):
        print(f"\n  [{index}] count={len(members)} state={state} names={names(members)}")
        for frame in frames[:frame_count]:
            print(f"      at {frame}")
        if not frames:
            print("      （无可识别栈帧）")
        elif len(frames) > frame_count:
            print(f"      … 省略 {len(frames) - frame_count} 个显示帧")
    omitted = sum(len(members) for _, members in ordered[top:])
    if omitted:
        print(f"\n其余 {len(ordered) - top} 组、{omitted} 个线程未展开。")

    print("\n关注路径索引（类别可重叠；每类最多显示 3 个线程及首个命中帧）：")
    for label, pattern in FOCUS:
        matches = []
        for block in blocks:
            matching_frame = next((frame for frame in block.frames if pattern.search(frame)), None)
            if matching_frame or pattern.search(block.name):
                matches.append((block, matching_frame))
        print(f"  {label}: {len(matches)}")
        for block, frame in matches[:3]:
            print(f"    L{block.line} {json.dumps(block.name, ensure_ascii=False)} [{block.state}]")
            if frame:
                print(f"      at {frame}")
        if len(matches) > 3:
            print(f"    … 其余 {len(matches) - 3} 个匹配线程未展开")


def print_lock_matches(blocks, address):
    matches = [block for block in blocks
               if any(int(match.group(), 16) == address for match in ADDRESS.finditer(block.raw))]
    print(f"\n地址 0x{address:x}：{len(matches)} 个关联线程块；这是引用检索，不是 owner 判定。")
    for block in matches:
        print(f"\n--- 原文件 L{block.line} 起 ---")
        print(block.raw.rstrip("\r\n"))
    if not matches:
        print("未找到引用；不代表锁不存在或没有 owner，可能未显示、已截断或地址来自其他快照。")
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="单个离线 Thread.print -l 文本文件")
    parser.add_argument("--top", type=bounded_integer(1, 10), default=10,
                        help="最多显示的完整栈分组数，1–10（默认 10）")
    parser.add_argument("--frames", type=bounded_integer(1, 12), default=6,
                        help="每组显示的栈帧数，1–12（默认 6）")
    parser.add_argument("--lock", type=lock_address, metavar="0xADDRESS",
                        help="仅打印同一 dump 中所有引用该地址的完整线程块；不判定 owner")
    args = parser.parse_args(argv)
    try:
        if not args.dump.is_file():
            raise ValueError("输入必须是现有普通文件")
        with args.dump.open("r", encoding="utf-8", errors="replace") as stream:
            blocks, warnings = parse_dump(stream, keep_raw=args.lock is not None)
    except (OSError, ValueError) as error:
        parser.exit(2, f"错误：{error}\n")
    print_limits(warnings)
    if args.lock is not None:
        return print_lock_matches(blocks, args.lock)
    print_summary(blocks, args.top, args.frames)
    return 0


if __name__ == "__main__":
    sys.exit(main())
