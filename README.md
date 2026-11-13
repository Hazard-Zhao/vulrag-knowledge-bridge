# Vul-RAG knowledge bridge

把已发布的 Vul-RAG 知识 JSON 接到越界保护条件 A/B/C/D 实验。脚本对漏洞版和修复版分别做代码 BM25 检索，并导出符合现有试跑格式的固定知识。检索与导出均在本机执行。

## 知识来源

| 版本 | 固定提交 | 文件 |
|---|---|---|
| [原 Vul-RAG](https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD/tree/38aa707fdb6bf592f1ed7753e90af400d3b9dcd3) | `38aa707fdb6bf592f1ed7753e90af400d3b9dcd3` | `vulnerability knowledge/linux_kernel_CWE-787_knowledge.json` |
| [RAG4SVD](https://github.com/hs-esslingen-it-security/RAG4SVD/tree/e67f8ded8f6f781d18ddb9d8356cfd07b90f4907) | `e67f8ded8f6f781d18ddb9d8356cfd07b90f4907` | `systems/vul-rag/add_vulnerability_knowledge/qwen2.5-coder-14b-instruct/linux_kernel_CWE-787_knowledge.json` |

RAG4SVD 一行对应从 PairVul 训练数据重建的知识。Oracle 库由测试数据生成，适用于单独的诊断。两套仓库的根目录均有 MIT 许可证。使用时从上游固定提交取得知识 JSON，仓库中仅维护接入代码和验证说明。

## 运行

在 D 盘的项目目录中运行。已有 spaCy、`rank-bm25` 和 `en_core_web_sm` 的环境可以直接执行。新环境可按以下方式安装依赖。

```powershell
$env:TMP = $env:TEMP = (Get-Location).Path
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --no-cache-dir -r requirements.txt
```

将下面的输入路径换成实际文件。每次运行使用新的输出目录。

```powershell
& .\.venv\Scripts\python.exe -B retrieve_pair.py `
  --kb 'D:/path/to/linux_kernel_CWE-787_knowledge.json' `
  --source 'owner/repository@commit' `
  --vulnerable 'D:/path/to/P15_before.c' `
  --patched 'D:/path/to/P15_after.c' `
  --exclude-cve CVE-2019-19332 `
  --out results/p15-original
```

脚本会排除指定 CVE，以及去掉空白后与任一输入版本完全相同的知识条目。可重复传入 `--exclude-cve`，用于排除同一评估批次的其他 CVE。该过滤只检查同 CVE 和完全相同代码，近重复仍需要另外审核。检索用代码单路 BM25，每个 CVE 最多一条，保留前三个正分候选。这个模式适用于离线接入验证。完整 Vul-RAG 还包含模型生成的用途、功能两路查询与下游漏洞判定。

- `retrieval.json` 记录两版各自的排名、分数、知识文件及输入的 SHA-256。
- `fixed_knowledge.json` 冻结漏洞版命中的三条知识。新一轮实验中，同一漏洞家族的各版本都使用这份文件，且 B/C/D 共用同一份。A 只用代码。用漏洞版来选共享知识适合当前配对诊断。对未知标签的部署评测，应另行定义各输入可用的查询信息。

## P15 接入验证

使用已有开发样本 `CVE-2019-19332` 的原始函数与上游修复函数。两库分别从 187 条降至 186 条。四次查询均返回以下排名：

1. CVE-2022-47942
2. CVE-2018-12714
3. CVE-2021-38166

两份固定知识均通过字段完整性检查。相同排序对应相同代码查询和候选代码，知识描述仍可能不同。这次验证只运行检索，未调用检测模型。
