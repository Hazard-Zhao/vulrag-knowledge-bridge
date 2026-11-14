# PairVul 1349 反例验证 · CVE-2017-16912（`get_pipe`，usbip stub_rx）

样本 ID：`pairvul:CWE-125:1349:before`（原版）/ `:after`（修复版）/ `:ineffective-01`（无效保护版）/ `:equivalent-01`（等价替代修复版）。

**验证范围（局部测试，非完整构建）**：只抽取 `get_pipe` 单函数做本地单元重放，用桩替代
USB helper（`dev_err`/`usb_endpoint_xfer_*`/`usb_*pipe`），并在 `ep_in[15]` 之后放置
canary 端点标记（`bDescriptorType=0xB2`）观察越界读。**不是**完整内核编译、**不是**
真实 USBIP 会话、**不是** AddressSanitizer。

## 上游补丁核对

- 文件：`drivers/usb/usbip/stub_rx.c`；`ep_in[16]`/`ep_out[16]` 各 16 项，索引用 `epnum & 0x7f`。
- 漏洞：`ep = udev->ep_in[epnum & 0x7f]` 未校验 `epnum` 上界，`epnum=16..127` 掩码后仍
  落在 16..127，越过 `ep_in[0..15]`（越界读，CWE-125）。
- 修复：加 `if (epnum < 0 || epnum > 15) goto err_ret;`，并把 `BUG()` 改为 `err_ret` 返回 -1。

## 四版对比（epnum = 16 是首个越界边界）

| 版本 | 检查 | epnum=16 是否越界读 |
|---|---|---|
| before（原版） | 无 | 是（读 ep_in[16]，读到 canary 0xB2） |
| after（修复版） | `> 15` | 否（拦截，返回 -1） |
| ineffective-01（无效保护） | `> 16` | 是（漏掉等号边界，读到 canary 0xB2） |
| equivalent-01（等价替代修复） | `>= 16` | 否（拦截，返回 -1） |

## 结论（本次实测）

见 `logs/*.log`。核心：`epnum=15` 四版都读 `ep_in[15]`（界内）；`epnum=16` 时
before / ineffective-01 都读到 canary 端点（越界读），after / equivalent-01 提前拦截；
`epnum=17` 时只有 before 越界，其余三版都拦截。即 `> 16` 漏掉了 `epnum == 16` 的等号边界
（仍是漏洞），而 `>= 16`（等价于 `> 15`）仍正确拦截。

## 复跑

```powershell
& <python> -X utf8 replay.py
```

依赖 `guard-validation/tools/tcc/tcc.exe`（已 gitignore）。产物：`logs/*.log`（入库）、
`results/<run_id>/`（evidence.jsonl/report.json，不入库）。
