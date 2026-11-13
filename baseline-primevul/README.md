# Vul-RAG on PrimeVul Paired

复现目标为 Retrieve, Reproduce, Reveal 表 2 的 Vul-RAG 行，摘要和检测均使用 Qwen/Qwen2.5-Coder-14B-Instruct。上游固定在 [RAG4SVD e67f8de](https://github.com/hs-esslingen-it-security/RAG4SVD/tree/e67f8ded8f6f781d18ddb9d8356cfd07b90f4907)。正式输入来自 `systems/vul-rag/data/test/primevul_CWE-*_testset.json`，对应知识来自 `vulnerability_knowledge_primevul_qwen14b`，按 CWE 分文件。运行参数来自作者的 `detect_benchmark.sh`。

## 已完成的离线重算

```powershell
python baseline-primevul/recount.py vendor/RAG4SVD results/primevul-rq2
```

用作者逐样本预测重算三轮，逐条核对结果里的输入代码与配对测试记录。三轮共同覆盖 425 对，正确对数分别为 92、97、86，均值 0.215686，样本标准差 0.012959。首轮按作者代码计算的 F1 为 0.554184，按漏洞正类单独计算的 F1 为 0.542823。作者的实现取正负两类平均 precision 和 recall 再求调和平均。作者计分把 final_result=-1 归入未报漏洞，-1 也可能由所有候选都没有触发判定产生，不能据此认定解析失败。作者公开汇总记录的解析率为 1.000，其分子尚未独立重算。

## 双人协作字段

- `pair_id` 采用 `rag4svd-rq2:primevul_CWE-787:15` 这样的格式，基于固定上游提交中的分桶和记录 ID。
- `sample_id` 在 pair_id 后加 `:before` 或 `:after`。派生版本可使用 `:ineffective-01` 或 `:equivalent-01`，对应验证证据另外记录。PairVul 或其他来源的样本应采用各自的数据集前缀。
- 每条预测记录包含 `run`、`pair_id`、`sample_id`、`variant`、`cve_id`、`cwe`、`label`、`prediction` 和 `evaluated_knowledge_cves`。知识 CVE 列表对应作者实际评估过的候选，可能因提前退出而短于完整检索列表。重算导出的标签与预测字段用于评估。

## 实际重跑入口

在具备 CUDA 和相应显存的机器上，按上游 `vul-rag-rep.yml` 准备环境，安装 spaCy 模型并缓存官方 checkpoint。作者用 L40S 48 GB 和 H100 80 GB。当前本机 RTX 4060 Laptop 只有约 8 GB 显存，无法在 GPU 内按原精度容纳 14B 权重。实际模型重跑待具备对应运行资源。

从 `systems/vul-rag` 目录先用独立输出路径验证 CWE-787 分桶。使用 Python 的 UTF-8 模式，避免 Windows 默认编码影响读取。

```powershell
New-Item -ItemType Directory -Force benchmark_results_vulrag/local-rq2-smoke
python -X utf8 src/vulnerability_detect_benchmark.py --input_file_name primevul_CWE-787_testset.json --output_file_name local-rq2-smoke/primevul_CWE-787.json --knowledge_file_name primevul_CWE-787_knowledge.json --knowledge_base_dir vulnerability_knowledge_primevul_qwen14b --model_name qwen2.5-coder-14b-instruct --summary_model_name qwen2.5-coder-14b-instruct --retrieval_top_k 20 --max_knowledge 3 --thread_pool_size 1 --resume --early_return --model_settings temperature=0.01
```

分桶跑通后，用上游 `detect_benchmark.sh qwen2.5-coder-14b-instruct` 运行全配置。使用独立上游工作副本保存新预测，避免其续跑参数读取作者发布的结果。
