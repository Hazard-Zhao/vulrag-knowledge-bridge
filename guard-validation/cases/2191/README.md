# Case 2191 — CVE-2019-19332（do_cpuid_func，CWE-787 越界写）

- `pair_id`: `pairvul:CWE-787:2191`
- `cve_id`: `CVE-2019-19332`
- `cwe`: CWE-787（越界写）
- `function`: `do_cpuid_func`（`arch/x86/kvm/cpuid.c`）

## 漏洞根因

`do_cpuid_func` 是 KVM CPUID 的入口，把 `entry` / `nent` / `maxnent` 透传给
`__do_cpuid_func` / `__do_cpuid_func_emulated`；真正的越界写在被调函数里——
它们写 `entry[(*nent)++]`，却没有在入口处检查 `*nent` 是否已满。修复在入口
补上下界保护：

```c
+	if (*nent >= maxnent)
+		return -E2BIG;
+
 	if (type == KVM_GET_EMULATED_CPUID)
 		return __do_cpuid_func_emulated(entry, func, nent, maxnent);
```

缺了这道门，`*nent` 到达 `maxnent` 后仍会继续写 `entry[maxnent]`（首个越界单元）。

## 四变体

| variant | 改动 | 期望标签 | 越界写（nent=4=maxnent） |
|---|---|---|---|
| before | 无检查 | 1 有漏洞 | ✅ 触发（entry[4]） |
| after | `*nent >= maxnent` | 0 无漏洞 | ❌ `-E2BIG` 拦截 |
| ineffective-01 | `*nent > maxnent`（漏等号） | 1 有漏洞 | ✅ 触发（entry[4]） |
| equivalent-01 | `maxnent <= *nent`（反转） | 0 无漏洞 | ❌ `-E2BIG` 拦截 |

## 验证范围（局部单元重放）

- 被调函数 `__do_cpuid_func` / `__do_cpuid_func_emulated` 用桩替代，桩执行
  `entry[(*nent)++] = …`（即真实越界写），并记录写入下标。
- `maxnent=4`，`entry` 用 4 单元 + canary 单元；`WRITE_INDEX >= 4` 即越界写，
  `CANARY_CHANGED` 佐证。
- 关键样例 `nent=4`（== maxnent）：`before` / `ineffective-01` 委托并写
  `entry[4]` 越界，`after` / `equivalent-01` 返回 `-E2BIG`。`nent=3` 四版均界内，
  `nent=5` 仅 `before` 越界（ineffective 的 `> maxnent` 也能拦下 5）。
- **不是**完整 KVM 构建、**不是** ASan；越界写发生在桩里，`do_cpuid_func` 是缺失的
  前门检查。

## 重放产物

- 源码：`before.c` / `after.c` / `ineffective.c` / `equivalent.c`
- harness：`do_cpuid_func_harness.c`
- 输入：`input.json`（nent = 3 / 4 / 5）
- 脚本：`replay.py`
- 日志：`logs/{before,after,ineffective-01,equivalent-01}.log`
