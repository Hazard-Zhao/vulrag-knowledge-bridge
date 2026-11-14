# Guard Validation · 反例验证侧

本分支负责反例验证：判断越界保护是否真的生效。基线侧（`baseline-primevul`）负责样本清单、模型配置、模型调用与预测记录；本侧只做本地编译、重放输入和执行证据，**不调用检测模型或任何收费 API**。

## 分工与交付

| 环节 | 基线侧 baseline-primevul | 本侧 guard-validation |
|---|---|---|
| 样本清单 | 维护统一 `pair_id` / `sample_id` 与评估标签 | 登记派生变体（无效保护、等价改写、调用方检查）及其父样本 |
| 模型预测 | 统一发起模型调用，产出 `predictions.jsonl` | 不重复跑同一批样本；需要新方法/新样本时先提交请求清单 |
| 执行证据 | 消费本侧证据做逐条对照 | 产出 `evidence.jsonl`、编译/执行日志、重放脚本与预期标签 |

反例按四类固定版本整理，每个版本单独记录到达的分支与写入点：

1. `original`：原始漏洞版本；
2. `developer_fix`：上游真实修复；
3. `ineffective-01`：无效保护（边界条件被削弱，例如 `>=` 错改为 `>`，等号边界仍触发）；
4. `equivalent-01`：等价条件改写；必要时另设 `caller-01` 表示保护上移到调用方。

## 标识与字段

字段契约以仓库根目录 [`shared/alignment-schema.json`](../shared/alignment-schema.json) 为准，对齐校验用 [`shared/validate_alignment.py`](../shared/validate_alignment.py)。

- `pair_id`：`<dataset>:<bucket>:<record_id>`，例如 `rag4svd-rq2:primevul_CWE-787:158`；本地自检样本用 `local-dev` 前缀，不进入正式评估集。
- `sample_id`：`<pair_id>:<variant>`，变体后缀见 schema 的 `enums.variant`。
- 证据记录与预测记录按 `(run, pair_id, sample_id, code_sha256)` 逐条对齐；缺项、哈希不一致、重复记录都在校验报告中显式列出，不静默丢弃。

## 目录

```
guard-validation/
  README.md
  validate.py                # 本地编译/重放/取证脚本，纯标准库，不调用模型
  samples/
    manifest.template.json   # 新样本清单模板：五版变体、角色、代码哈希、预期标签
    cpuid/                   # 已接入的开发自检样本（CVE-2019-19332，五版桩 + 来源记录）
  evidence.template.jsonl    # 证据记录模板（一行一条）
  results/<run_id>/          # 编译产物、日志、evidence.jsonl、report.json（已 gitignore）
  tools/                     # 便携编译器等本地工具二进制（已 gitignore，不入库）
```

## 验证边界

- `not_triggered` 只表示当前记录的输入没有触发，不能直接等同于一般意义上的安全。
- 本地桩/哨兵检查不等于完整内核复现、ASan 检测或全部输入语义等价；每条证据必须在 `validation_method` 里写清实际覆盖范围。
- 代码哈希绑定实际参与验证的文件：若模型输入只是目标函数而哈希来自整个验证桩，需另存模型代码并独立计算哈希，不能拿桩哈希冒充模型代码哈希。
- 新反例按独立样本目录和 manifest 加入，不覆盖已有快照；代码哈希变化就创建新样本版本。

## 本地运行（自检样本）

脚本只依赖 Python 标准库；准备一个 Python 3.11+ 解释器和 `tools/tcc` 便携编译器后：

```powershell
python -X utf8 validate.py
```

每次运行生成独立 `results/<run_id>/`，含环境与工具哈希、编译/执行日志、逐输入观察、`evidence.jsonl` 和 `report.json`。退出码非零表示验证未通过。证据产出后，用根目录 `shared/validate_alignment.py` 与基线预测逐条对齐。
