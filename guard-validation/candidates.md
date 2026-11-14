# 20-CVE 反例候选清单（provisional）

目标：20 个独立 CVE，四类各 5，每 CVE 只归一类。来源为 PrimeVul/PairVul 冻结清单
（KnowledgeRAG4LLMVulD @ 38aa707，本机 `vul-rag-pilot/data/expansion/raw/CWE-*_testset.json`）；
case 158 来自 RAG4SVD PrimeVul（单独来源）。

| 类 | variant | 期望标签 | CVE（pair_id） |
|---|---|---|---|
| ① 原始漏洞版 | before | 1 有漏洞 | CVE-2022-1533（158，✅已重放）· CVE-2020-10742 · CVE-2016-9755 · CVE-2015-5327 · CVE-2017-8067 |
| ② 有效修复版 | after | 0 无漏洞 | CVE-2022-20369 · CVE-2020-25212 · CVE-2022-2991 · CVE-2021-4093 · CVE-2023-3090 |
| ③ 无效保护 | ineffective-01 | 1 有漏洞 | CVE-2021-37576（3058，✅已重放）· CVE-2019-19332（cpuid，dev 夹具）· CVE-2017-16912 · CVE-2019-0149 · CVE-2013-4587 |
| ④ 等价替代修复 | equivalent-01 | 0 无漏洞 | CVE-2014-7825 · CVE-2013-1772 · CVE-2020-28915 · CVE-2021-38201 · CVE-2016-9083 |

重放状态：`replayed`（已完成并入库）· `dev_fixture`（cpuid 已建 V0-V4，需从冻结记录 2191 重建为 pairvul 口径）· `pending`（待建 harness 重放）。

**入选门槛**：可追溯源码提交 + 对齐函数 + 完成输入重放；不足 5 记缺口、不凑数。
完整机器可读版见 `candidates.json`。
