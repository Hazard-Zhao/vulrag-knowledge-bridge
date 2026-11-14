# PrimeVul 158 反例验证 · CVE-2022-1533（libmobi `mobi_decode_infl`）

样本 ID：`rag4svd-rq2:primevul_CWE-787:158:before`（漏洞版）/ `:after`（修复版）。

**验证范围（局部测试，非完整构建）**：只抽取 `mobi_decode_infl` 单个函数做本地单元重放，
用构造的 `rule` + 带哨兵字节（canary）的 `decoded` 缓冲区驱动删除分支；**不是**完整 libmobi 编译、
**不是**真实 .mobi 文件解析、**不是** AddressSanitizer。`decoded[-1]` 是 backing 数组内真实存在的
一个字节（哨兵），因此越界读/写可被观察到而不会直接崩溃。

## 上游补丁核对

- 漏洞版 commit：`afa8ce1cd73429b5c37c9f6c55252f3329d38de8`
- 修复版 commit：`eafc415bc6067e72577f70d6dd5acbf057ce6e6f`（消息：*Fix wrong boundary checks in
  inflections parser resulting in stack buffer over-read with corrupt input*）

补丁只改 `src/index.c` 的三处（`INDX_INFLBUF_SIZEMAX = 500`）：

| 位置 | 漏洞版 | 修复版 |
|---|---|---|
| 设置位置分支 | `if (pos < 0 \|\| pos > *decoded_size) return` | 该检查被删除 |
| 插入分支上界 | `l < 0 \|\| d + l > …` | `pos < 0 \|\| l < 0 \|\| d + l > …` |
| 删除分支上界 | `l < 0 \|\| d + l > …` | `pos < 0 \|\| l < 0 \|\| s + l > …` |

关键点：漏洞版的 `pos` 下界检查只存在于“设置位置”分支；删除分支 `if (dir == '<') pos--;` 之后
**没有**再次校验 `pos >= 0`，随后仍会读 `decoded[pos]`。

## 输入（input.json）

| case | decoded | canary(decoded[-1]) | rule(hex) | 预期差异 |
|---|---|---|---|---|
| `read` | `"A"` | `@`=64 | `0b 03 58` | 漏洞版读 `decoded[-1]` 报 mismatch；修复版先拦截 |
| `write` | `"A"` | `X`=88 | `0b 03 58` | 漏洞版过 mismatch 后 `memmove` 写越界；修复版仍拦截 |
| `insert-after-delete` | `"A"` | `X`=88 | `0b 03 58 02 42` | 删除后 pos=-1，0x02 重选插入（不改方向），漏洞版进入插入分支再写 `decoded[-1]='B'`；修复版仍在删除分支拦截 |

`rule` 解释：`0x0b` 设置位置（`pos -= 1`，从 1→0）；`0x03` 删除/向左；`0x58`=`'X'` 数据字节，
触发 `dir=='<'` 时 `pos--` 使 `pos` 从 0 变 **-1**。

## 结论（本次实测）

删除分支执行 `pos--` 后，两版 `pos` 都变成 **-1**，但行为不同：

- **漏洞版**：未提前拦截，继续访问 `decoded[-1]`——日志出现
  `Character mismatch in A at pos: -1 (@ != X)`（读到哨兵字节），`write` case 中哨兵由 `X` 被改为 `A`，
  证明还发生越界写。
- **修复版**：先命中 `pos < 0` 检查，日志出现 `Out of buffer in A at pos: -1`，返回
  `MOBI_DATA_CORRUPT`，**没有**读取 `decoded[pos]`，哨兵不变。

即：漏洞是“删除分支 `pos--` 后缺少 `pos < 0` 下界保护，导致 `decoded[-1]` 越界读（CWE-125/126，
PrimeVul 分桶记作 CWE-787）”。

**关于“后续插入分支/控制字重置 pos”（基线侧核验问题）**：`insert-after-delete` case 证实——
删除分支 `pos--` 使 `pos=-1` 后，若后续是**不改方向**的命令字节（0x02 重选插入），`pos` 不会被重置，
插入分支会用 `pos=-1` 再次访问 `decoded[-1]`（哨兵被写成 `'B'`）。但这是**同一根因**的次级表现：
修复版在删除分支的 `pos < 0` 检查处就已提前返回，根本走不到插入分支；漏洞版的首次越界访问
已发生在删除分支本身的 `decoded[pos]` 读取处。若中间出现**改变方向**的命令字节，`pos` 会被重置，
插入分支的负下标才被避开——与基线侧“控制字可能重置 pos”的推测一致。

## 复跑

```powershell
& <python> -X utf8 replay.py
```

依赖 `guard-validation/tools/tcc/tcc.exe`（已 gitignore）。每次运行在 `results/<run_id>/` 下产出
`before.log`、`after.log`、`evidence.jsonl`、`report.json`；证据字段对齐 `shared/alignment-schema.json`。

> 说明：证据里的 `code_sha256` 是抽取函数文件 `before.c`/`after.c` 的哈希；与基线预测联表前，
> 需先与基线测试集代码片段的哈希口径对齐。
