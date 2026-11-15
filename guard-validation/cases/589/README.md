# Case 589 — CVE-2014-7825（ftrace_syscall_exit，CWE-125 越界读）

- `pair_id`: `pairvul:CWE-125:589`
- `cve_id`: `CVE-2014-7825`
- `cwe`: CWE-125（越界读）
- `function`: `ftrace_syscall_exit`（`kernel/trace/trace_syscalls.c`）
- 修复提交标题：`tracing/syscalls: Ignore numbers outside NR_syscalls' range`（精确 hash 待核实）

## 漏洞根因

`ftrace_syscall_exit` 对 `trace_get_syscall_nr()` 返回的 `syscall_nr` 只做了下界检查：

```c
syscall_nr = trace_get_syscall_nr(current, regs);
if (syscall_nr < 0)        /* 只查下界 */
    return;
ftrace_file = rcu_dereference_sched(tr->exit_syscall_files[syscall_nr]);  /* 越界读 */
```

`tr->exit_syscall_files` 长度是 `NR_syscalls`（0..NR_syscalls-1）。当 `syscall_nr >= NR_syscalls`
时，`exit_syscall_files[syscall_nr]` 越过数组末尾，属越界读（CWE-125）。CVE 描述为
“private syscall numbers 处理不当”。

修复补丁（一行）：

```c
-	if (syscall_nr < 0)
+	if (syscall_nr < 0 || syscall_nr >= NR_syscalls)
```

## 四变体

| variant | 代码改动 | 期望标签 | 越界读（nr=16） |
|---|---|---|---|
| before | 原样 `if (syscall_nr < 0)` | 1 有漏洞 | ✅ 触发 |
| after | 官方修复 `>= NR_syscalls` | 0 无漏洞 | ❌ 拦截 |
| ineffective-01 | 弱化 `> NR_syscalls`（漏等号） | 1 有漏洞 | ✅ 触发 |
| equivalent-01 | 等价重排 `>= NR_syscalls \|\| < 0` | 0 无漏洞 | ❌ 拦截 |

关键样例 `syscall_nr = 16`（== NR_syscalls，第一个越界下标）：`before` / `ineffective-01`
执行 `exit_syscall_files[16]` 越界读（`READ_INDEX=16, OOB_READ=1`）；`after` /
`equivalent-01` 在边界检查处提前返回（`INTERCEPTED=1`，无读）。

## 验证范围（局部单元重放）

- `NR_syscalls` 缩小为 16（本机重放用），越界判定逻辑不变；`exit_syscall_files[16]` 用
  8 字节 canary 背板。
- `rcu_dereference_sched` 用宏桩记录被解引用的地址，`READ_INDEX` 直接给出越界下标，
  无需 ASan。
- 内核辅助（`trace_get_syscall_nr` / `ftrace_trigger_soft_disabled` / `syscall_nr_to_meta`
  / 锁、缓冲区等）全部桩到最小契约；**不是**完整内核构建、**不是** ASan。

## 重放产物

- 源码：`before.c` / `after.c` / `ineffective.c` / `equivalent.c`（逐字函数副本，仅改函数名后缀）
- harness：`ftrace_syscall_exit_harness.c`
- 输入：`input.json`（syscall_nr = -1 / 15 / 16 / 17）
- 脚本：`replay.py`（编译 + 逐用例跑 + 写 `evidence.jsonl` / `report.json`）
- 日志：`logs/{before,after,ineffective-01,equivalent-01}.log`
