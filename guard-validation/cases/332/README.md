# Case 332 — CVE-2013-4587（kvm_vm_ioctl_create_vcpu，CWE-20 输入校验）

- `pair_id`: `pairvul:CWE-20:332`
- `cve_id`: `CVE-2013-4587`
- `cwe`: CWE-20（输入校验缺失）
- `function`: `kvm_vm_ioctl_create_vcpu`（`virt/kvm/kvm_main.c`）

## 漏洞根因

创建 vCPU 时未校验 `id` 上界；`id` 会变成 `vcpu->vcpu_id`，后续在 KVM 其他
代码里被当作数组下标使用，导致越界（CVE 描述的“array index error”）。修复在
入口补上输入校验：

```c
+	if (id >= KVM_MAX_VCPUS)
+		return -EINVAL;
+
 	vcpu = kvm_arch_vcpu_create(kvm, id);
```

## 四变体

| variant | 改动 | 期望标签 | 越界保护被绕过（id=4=KVM_MAX_VCPUS） |
|---|---|---|---|
| before | 无检查 | 1 有漏洞 | ✅ 继续 `kvm_arch_vcpu_create` |
| after | `id >= KVM_MAX_VCPUS` | 0 无漏洞 | ❌ `-EINVAL` 拦截 |
| ineffective-01 | `id > KVM_MAX_VCPUS`（漏等号） | 1 有漏洞 | ✅ 继续（4 未被拦） |
| equivalent-01 | `!(id < KVM_MAX_VCPUS)` | 0 无漏洞 | ❌ `-EINVAL` 拦截 |

关键样例 `id=4`（== KVM_MAX_VCPUS）：`before` / `ineffective-01` 继续调用
`kvm_arch_vcpu_create`（保护被绕过），`after` / `equivalent-01` 返回 `-EINVAL`。

## 验证范围（guard-only 局部重放）

- 这是**保护（guard）级**重放：观察「`id >= KVM_MAX_VCPUS` 时函数是否仍继续创建
  vCPU」，即缺失校验的前置条件。真正的越界发生在 KVM 其他代码里（`vcpu_id` 作下标），
  **不在**本单元重放范围内。
- `kvm_arch_vcpu_create` 用桩记录「是否被调用 + 传入的 id」；其余内核依赖
  （mutex / atomic / 遍历宏 / fd 创建等）桩为 no-op。
- `KVM_MAX_VCPUS` 桩为 4（上游为 1024）。**不是**完整 KVM 构建、**不是** ASan。

## 重放产物

- 源码：`before.c` / `after.c` / `ineffective.c` / `equivalent.c`
- harness：`kvm_vm_ioctl_create_vcpu_harness.c`
- 输入：`input.json`（id = 3 / 4 / 5）
- 脚本：`replay.py`
- 日志：`logs/{before,after,ineffective-01,equivalent-01}.log`
