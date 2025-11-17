#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 ftrace/perf 类似日志中统计所有调用关系的时间（支持嵌套）。
输入行示例：
732768 [004] 154939.925854842:   call   ffffffff85b516cc do_syscall_64+0x2c => ffffffff851c1830 __x64_sys_futex+0x0
732768 [004] 154939.925854981:   return ffffffff851bf229 futex_wake+0xa9   => ffffffff851c1075 do_futex+0xc5
"""

import re
import csv
import sys
from collections import defaultdict, deque
from math import inf

import argparse

CALL_RE = re.compile(
    r"""^\s*(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<ts>\d+\.\d+):\s+call\s+
        [0-9a-fA-Fx]+\s+(?P<src_sym>[A-Za-z0-9_]+)\+\w+\s=>\s
        [0-9a-fA-Fx]+\s+(?P<dst_sym>[A-Za-z0-9_]+)\+\w+""",
    re.X
)

RET_RE = re.compile(
    r"""^\s*(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<ts>\d+\.\d+):\s+return\s+
        [0-9a-fA-Fx]+\s+(?P<ret_sym>[A-Za-z0-9_]+)\+\w+\s=>\s
        [0-9a-fA-Fx]+\s+(?P<parent_sym>[A-Za-z0-9_]+)\+\w+""",
    re.X
)

def parse_args():
    ap = argparse.ArgumentParser(description="统计日志中的调用/返回耗时")
    ap.add_argument("logfile", help="输入日志文件路径")
    ap.add_argument("--key-by-cpu", action="store_true",
                    help="调用栈按 (pid,cpu) 维度区分（默认仅按pid）")
    ap.add_argument("--events-csv", default="events.csv", help="明细输出文件")
    ap.add_argument("--func-stats-csv", default="func_stats.csv", help="按函数统计输出")
    ap.add_argument("--callgraph-stats-csv", default="callgraph_stats.csv", help="按调用边统计输出")
    return ap.parse_args()

def main():
    args = parse_args()

    # 每个键（pid 或 (pid,cpu)）维护一个栈：[(callee, caller, enter_ts)]
    stacks = defaultdict(deque)

    # 聚合
    func_cnt = defaultdict(int)
    func_sum = defaultdict(float)
    func_min = defaultdict(lambda: inf)
    func_max = defaultdict(lambda: -inf)

    edge_cnt = defaultdict(int)           # key = (caller, callee)
    edge_sum = defaultdict(float)
    edge_min = defaultdict(lambda: inf)
    edge_max = defaultdict(lambda: -inf)

    events = []  # (pid, cpu, depth, caller, callee, t0, t1, dur_us)

    with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = CALL_RE.match(line)
            if m:
                pid = int(m.group("pid"))
                cpu = int(m.group("cpu"))
                ts  = float(m.group("ts"))     # 秒
                caller = m.group("src_sym")    # 调用发起方（左符号）
                callee = m.group("dst_sym")    # 被调（右符号）

                key = (pid, cpu) if args.key_by_cpu else pid
                depth = len(stacks[key])
                stacks[key].append((callee, caller, ts, depth))
                continue

            m = RET_RE.match(line)
            if m:
                pid = int(m.group("pid"))
                cpu = int(m.group("cpu"))
                ts  = float(m.group("ts"))     # 秒
                ret_sym = m.group("ret_sym")   # 返回的函数（左符号）= 栈顶 callee
                parent_sym = m.group("parent_sym")  # 返回到的上层（右符号）= 栈顶 caller

                key = (pid, cpu) if args.key_by_cpu else pid
                if not stacks[key]:
                    continue  # 异常：无栈可弹，跳过

                # 正常情况：栈顶应与 ret_sym 匹配；若日志有乱序，向上回溯找到匹配帧
                # （极少发生，若找不到，放弃该return）
                idx = None
                for i in range(len(stacks[key])-1, -1, -1):
                    if stacks[key][i][0] == ret_sym:
                        idx = i
                        break
                if idx is None:
                    continue

                # 弹出 idx 以及其上的所有帧直到 idx（通常 idx 就是栈顶）
                while len(stacks[key]) - 1 > idx:
                    stacks[key].pop()
                callee, caller, t0, depth = stacks[key].pop()

                # 可选一致性检查：parent_sym == caller（偶尔会因偏移不同而不完全一致）
                # 这里不强制要求

                dur_us = (ts - t0) * 1e6

                # 记录明细
                events.append((pid, cpu, depth, caller, callee, t0, ts, dur_us))

                # 函数聚合（按 callee 统计）
                func_cnt[callee] += 1
                func_sum[callee] += dur_us
                func_min[callee] = min(func_min[callee], dur_us)
                func_max[callee] = max(func_max[callee], dur_us)

                # 调用边聚合（caller->callee）
                edge = (caller, callee)
                edge_cnt[edge] += 1
                edge_sum[edge] += dur_us
                edge_min[edge] = min(edge_min[edge], dur_us)
                edge_max[edge] = max(edge_max[edge], dur_us)

    # 写出明细
    with open(args.events_csv, "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["pid", "cpu", "depth", "caller", "callee",
                    "enter_ts_sec", "exit_ts_sec", "duration_us"])
        for r in events:
            pid, cpu, depth, caller, callee, t0, t1, dt = r
            w.writerow([pid, cpu, depth, caller, callee,
                        f"{t0:.9f}", f"{t1:.9f}", f"{dt:.3f}"])

    # 写出函数统计
    with open(args.func_stats_csv, "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["function", "count", "total_us", "avg_us", "min_us", "max_us"])
        for func, cnt in sorted(func_cnt.items(), key=lambda x: -func_sum[x[0]]):
            total = func_sum[func]
            avg = total / cnt if cnt else 0.0
            w.writerow([func, cnt, f"{total:.3f}", f"{avg:.3f}",
                        f"{func_min[func]:.3f}", f"{func_max[func]:.3f}"])

    # 写出调用边统计
    with open(args.callgraph_stats_csv, "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["caller", "callee", "count", "total_us", "avg_us", "min_us", "max_us"])
        for (caller, callee), cnt in sorted(edge_cnt.items(), key=lambda x: -edge_sum[x[0]]):
            total = edge_sum[(caller, callee)]
            avg = total / cnt if cnt else 0.0
            w.writerow([
                caller, callee, cnt,
                f"{total:.3f}", f"{avg:.3f}",
                f"{edge_min[(caller, callee)]:.3f}",   # ← 修复这里
                f"{edge_max[(caller, callee)]:.3f}"
            ])



    # 友好提示：未闭合栈帧数
    unclosed = sum(len(v) for v in stacks.values())
    if unclosed:
        sys.stderr.write(f"[warn] 存在 {unclosed} 个未闭合的调用帧（日志可能被截断或乱序）。\n")

if __name__ == "__main__":
    main()

