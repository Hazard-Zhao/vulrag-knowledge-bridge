# 反例候选清单（provisional，数量目标已撤回）

> 原「四类各 5、20 个独立 CVE」的数量目标**已撤回**（未经候选库核验，不设硬指标）。
> 现改为按 **可追溯提交 + 函数对齐 + 可重放** 逐项筛候选并记录状态；不足/凑不出即记缺口，不凑数。
> **类别标在样本/版本（variant）上**，CVE 仅作去重与统计分组键；同一 CVE 的多个变体可保留在同一组内。

来源：PairVul（KnowledgeRAG4LLMVulD @ 38aa707，本机 `vul-rag-pilot/data/expansion/raw/CWE-*_testset.json`）；case 158 来自 RAG4SVD PrimeVul（单独来源）。

## 已核验（7 个 CVE）

| CVE | pair_id | 函数 | 已重放变体 | 主要入集版本（类别） |
|---|---|---|---|---|
| CVE-2022-1533 | rag4svd-rq2:primevul_CWE-787:158 | mobi_decode_infl | before / after | before（①原始漏洞版） |
| CVE-2021-37576 | pairvul:CWE-787:3058 | kvmppc_rtas_hcall | 四变体 | ineffective-01（③无效保护） |
| CVE-2017-16912 | pairvul:CWE-125:1349 | get_pipe | 四变体 | ineffective-01（③无效保护） |
| CVE-2014-7825 | pairvul:CWE-125:589 | ftrace_syscall_exit | 四变体 | before（①原始漏洞版） |
| CVE-2020-28915 | pairvul:CWE-125:2660 | fbcon_get_font | 四变体 | ineffective-01（③无效保护） |
| CVE-2019-19332 | pairvul:CWE-787:2191 | do_cpuid_func | 四变体 | before（①原始漏洞版） |
| CVE-2013-4587 | pairvul:CWE-20:332 | kvm_vm_ioctl_create_vcpu | 四变体 | before（①，guard-only） |

其余变体（after/equivalent-01/before 等）保留在各自 CVE 组内作对照，不计入对应类别数量。

## 候选池（逐项筛后记缺口，不凑数）

| 函数 | pair_id | 补丁形态 | 结论 |
|---|---|---|---|
| i40e_vc_config_queues_msg | pairvul:CWE-20:1880 | `if (idx >= ARRAY_SIZE(vf->ch))` | 缺口（idx 由 ADQ 通道状态驱动） |
| console_unlock | pairvul:CWE-119:171 | `if (len+1 >= sizeof(text))` | 缺口（大重构，非单一边界） |
| xdr_set_page_base | pairvul:CWE-119:3075 | `if (base >= maxlen)` | 缺口（clamp→return 语义变化） |
| vfio_pci_ioctl | pairvul:CWE-119:1137 | `if (hdr.count >= (U32_MAX - hdr.start))` | 缺口（大函数+整数溢出） |
| ll_free_user_pages | pairvul:CWE-787:2409 | — | 缺口（内存管理/UAF 语义） |
| nf_ct_frag6_gather | pairvul:CWE-787:1162 | — | 缺口（错误码变化） |
| x509_decode_time | pairvul:CWE-125:776 | `if (mon < 1 \|\| mon > 12)` 前移 | 缺口（GNU 语句表达式 + static const 难加 canary） |
| put_chars | pairvul:CWE-787:1541 | — | 缺口（kmemdup 生命周期） |

完整机器可读版见 `candidates.json`；缺口原因逐条见 `gaps.json`。
