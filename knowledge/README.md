# CWE-787 知识库

两份 JSON 各含 187 条知识，保留 CVE、用途、功能、漏洞触发条件、成因与修复行为。RAG4SVD 版本还保留上游记录 ID。发布版省略漏洞前后源码和补丁行字段。

| 文件 | 固定来源 |
|---|---|
| `vulrag-original-cwe787.json` | [原 Vul-RAG 发布库](https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD/blob/38aa707fdb6bf592f1ed7753e90af400d3b9dcd3/vulnerability%20knowledge/linux_kernel_CWE-787_knowledge.json) |
| `rag4svd-pairvul-qwen14b-cwe787.json` | [RAG4SVD 的 PairVul 训练知识库](https://github.com/hs-esslingen-it-security/RAG4SVD/blob/e67f8ded8f6f781d18ddb9d8356cfd07b90f4907/systems/vul-rag/add_vulnerability_knowledge/qwen2.5-coder-14b-instruct/linux_kernel_CWE-787_knowledge.json) |

两份库用于提供历史漏洞知识。进行评估时，先排除测试 CVE，并依据实验协议选择条目。复跑 README 中的代码 BM25 实验时，从上游链接获取带源码字段的原始 JSON。仓库中的两份发布版适用于读取知识文本。

`manifest.json` 记录条目数与 SHA-256。两份上游 MIT 许可证随数据保留。
