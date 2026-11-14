# PrimeVul 158 · libmobi 漏报记录

目标为 CVE-2022-1533 的 `mobi_decode_infl`，样本 ID 为 `rag4svd-rq2:primevul_CWE-787:158:before`。DeepSeek Flash 批次 `deepseek-cwe787-batch-001` 中，漏洞版标签为 1，判定为 0。对应 `:after` 的标签和判定均为 0。

| 实际评估顺序 | 历史知识 | 漏洞行为 | 修复行为 | 处理结果 |
|---|---|---|---|---|
| 1 | CVE-2020-16309 | NO | NO | 继续评估 |
| 2 | CVE-2018-18557 | YES | YES | 提前返回 0 |

[原始证据](before-candidate-2.json)保留第二条历史知识及两段模型原答。该历史案例讲的是 JBIG 解码时未核对解码大小与目标缓冲区容量。漏洞回答指出，libmobi 的 `l < 0` 和复制终点检查可能放过负 `pos`。修复回答把同一组上界检查以及只在设置位置分支生效的检查视为有效防护。

上游判定脚本第 391 行要求“漏洞 YES 且修复 NO”才返回 1。第 399 行在启用 `early_return` 且修复为 YES 时进入提前退出分支，第 405 行返回 0。这里的 YES/YES 确定地触发了提前退出。现有日志仅记录实际评估的条目，无法从中确定后续候选及其判定。 [固定上游判定代码](https://github.com/hs-esslingen-it-security/RAG4SVD/blob/e67f8ded8f6f781d18ddb9d8356cfd07b90f4907/systems/vul-rag/src/vulnerability_detect_benchmark.py#L388-L405)

给重放侧核验的具体问题是：`dir == '<'` 且进入删除分支时，`pos--` 能否产生负下标并到达首次 `decoded[pos]` 访问。原答另外推测可以转到后续插入分支，控制字可能重置 `pos`，这条路径仍需单独验证。当前记录来自已有模型日志和代码检查，未执行 libmobi 重放。
