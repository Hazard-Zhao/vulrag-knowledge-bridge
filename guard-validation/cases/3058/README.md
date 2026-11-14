# PairVul 3058 反例验证 · CVE-2021-37576（`kvmppc_rtas_hcall`，RTAS）

样本 ID：`pairvul:CWE-787:3058:before`（原版）/ `:after`（修复版）/ `:ineffective-01`（无效保护版）/ `:equivalent-01`（等价替代修复版）。

**验证范围（局部测试，非完整构建）**：只抽取 `kvmppc_rtas_hcall` 单函数做本地单元重放，
用桩替代内核 helper（`kvm_read_guest`/`list_for_each_entry`/`mutex_*` 等），并用紧跟在
`args.args[16]` 之后的哨兵（canary）字节观察越界写。**不是**完整内核编译、**不是**真实
KVM 客户机、**不是** AddressSanitizer。

## 上游补丁核对

- 修复 commit：`f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a`（*KVM: PPC: Book3S: Fix H_RTAS
  rets buffer overflow*）；引入 commit `8e591cb7204739efa8e15967ea334eb367039dde`。
- 文件：`arch/powerpc/kvm/book3s_rtas.c`；CVE 描述指 `rtas_args.nargs` 越界导致宿主内存破坏。
- `struct rtas_args` 的 `args[16]`，即 `ARRAY_SIZE(args.args) == 16`。

补丁只加一处上界检查：

```c
orig_rets = args.rets;
if (be32_to_cpu(args.nargs) >= ARRAY_SIZE(args.args)) {   /* 修复版新增 */
    rc = -EINVAL;
    goto fail;
}
args.rets = &args.args[be32_to_cpu(args.nargs)];
```

关键点：`args.rets = &args.args[nargs]` 之后 handler 会写 `rets[0]`；当 `nargs == 16` 时，
`rets` 指向 `args.args[16]`（越过 `args[0..15]`）。

## 四版对比

| 版本 | 检查 | nargs=16 是否进 handler | 是否越界写 |
|---|---|---|---|
| before（原版） | 无 | 是 | 是（写 args[16]） |
| after（修复版） | `>=` | 否（拦截，返回 -EINVAL） | 否 |
| ineffective-01（无效保护） | `>` | 是（漏掉等号边界） | 是（写 args[16]） |
| equivalent-01（等价替代修复） | `> ARRAY_SIZE-1` | 否（拦截，返回 -EINVAL） | 否 |

## 结论（本次实测）

见 `logs/*.log`。核心：nargs=15 四版都写 `args[15]`（界内）；nargs=16 时 before/ineffective-01
都进入 handler 并写 `args[16]`（越界，canary 被改写），after/equivalent-01 提前拦截；nargs=17 时
before 越界，其余三版都拦截。即 `> 16` 漏掉了 `nargs == 16` 的等号边界（仍是漏洞），而
`> 15`（等价于 `>= 16`）仍正确拦截。

## 复跑

```powershell
& <python> -X utf8 replay.py
```

依赖 `guard-validation/tools/tcc/tcc.exe`（已 gitignore）。产物：`logs/*.log`（入库）、
`results/<run_id>/`（evidence.jsonl/report.json，不入库）。
