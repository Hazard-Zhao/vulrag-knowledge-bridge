# Case 2660 — CVE-2020-28915（fbcon_get_font，CWE-125 越界读）

- `pair_id`: `pairvul:CWE-125:2660`
- `cve_id`: `CVE-2020-28915`
- `cwe`: CWE-125（越界读）
- `function`: `fbcon_get_font`（`drivers/video/fbdev/core/fbcon.c`）
- 修复提交：`fbcon: Fix out-of-bounds read in fbcon_get_font`（CID-`6735b4632def`，全 hash 待核实）

## 漏洞根因

`fbcon_get_font` 把字体位图逐字符拷出，循环 `charcount` 次、每次 `fontdata += j`，
总计读 `charcount * j` 字节。原代码没有检查 `charcount * j` 是否超过字体数据缓冲
`FNTSIZE(fontdata)`；高字库（`vc_hi_font_mask` 置位 → `charcount = 512`）时
`512 * 16 = 8192 > 4096`，`fontdata` 越过缓冲末尾，属越界读（CWE-125）。

修复补丁（在每个分支循环前加尺寸检查）：

```c
	j = vc->vc_font.height;
+	if (font->charcount * j > FNTSIZE(fontdata))
+		return -EINVAL;
	for (i = 0; i < font->charcount; i++) { ... }
```

## 四变体

| variant | 改动 | 期望标签 | 越界读（hi_font=1） |
|---|---|---|---|
| before | 无检查 | 1 有漏洞 | ✅ 触发 |
| after | 官方修复 `charcount * j > FNTSIZE` | 0 无漏洞 | ❌ 拦截 |
| ineffective-01 | 错变量 `j > FNTSIZE`（只查高度，恒假） | 1 有漏洞 | ✅ 触发 |
| equivalent-01 | 等价反转 `FNTSIZE < charcount * j` | 0 无漏洞 | ❌ 拦截 |

关键样例 `hi_font=1`（charcount=512，j=16，`512*16=8192 > FNTSIZE=4096`）：
`before` / `ineffective-01` 循环读越界（输出 `data` 出现 canary 字节 `0xAA`，`OOB_READ=1`）；
`after` / `equivalent-01` 在尺寸检查处 `return -EINVAL`（`RET=-22`，无越界读）。

## 验证范围（局部单元重放）

- `FNTSIZE(fontdata)` 桩为 harness 缓冲区大小 4096（真实内核从字体头算，CID-6735b4632def）。
- `fontdata` 用 0x11 填充 + 其后再铺 0xAA canary 区；输出 `data` 用 0x00 起底，
  越界读表现为 `data` 中出现 0xAA。**不是** ASan、**不是**完整内核构建。
- 只走第一个分支 `font->width <= 8`（`j = vc_font.height`）。

## 重放产物

- 源码：`before.c` / `after.c` / `ineffective.c` / `equivalent.c`（逐字函数副本，仅改函数名后缀）
- harness：`fbcon_get_font_harness.c`
- 输入：`input.json`（hi_font = 0 / 1）
- 脚本：`replay.py`
- 日志：`logs/{before,after,ineffective-01,equivalent-01}.log`
