# 反例候选清单（provisional，数量目标已撤回）

> 原「四类各 5、20 个独立 CVE」的数量目标**已撤回**（未经候选库核验，不设硬指标）。
> 现改为按 **可追溯提交 + 函数对齐 + 可重放** 逐项筛候选并记录状态；不足/凑不出即记缺口，不凑数。
> **类别标在样本/版本（variant）上**，CVE 仅作去重与统计分组键；同一 CVE 的多个变体可保留在同一组内。

来源：PairVul（KnowledgeRAG4LLMVulD @ 38aa707，本机 `vul-rag-pilot/data/expansion/raw/CWE-*_testset.json`）；case 158 来自 RAG4SVD PrimeVul（单独来源）。

## 已核验（6 个 CVE）

| CVE | pair_id | 函数 | 已重放变体 | 主要入集版本（类别） |
|---|---|---|---|---|
| CVE-2022-1533 | rag4svd-rq2:primevul_CWE-787:158 | mobi_decode_infl | before / after | before（①原始漏洞版） |
| CVE-2021-37576 | pairvul:CWE-787:3058 | kvmppc_rtas_hcall | 四变体 | ineffective-01（③无效保护） |
| CVE-2017-16912 | pairvul:CWE-125:1349 | get_pipe | 四变体 | ineffective-01（③无效保护） |
| CVE-2014-7825 | pairvul:CWE-125:589 | ftrace_syscall_exit | 四变体 | before（①原始漏洞版） |
| CVE-2020-28915 | pairvul:CWE-125:2660 | fbcon_get_font | 四变体 | ineffective-01（③无效保护） |
| CVE-2019-19332 | pairvul:CWE-787:2191 | do_cpuid_func | 四变体 | before（①原始漏洞版） |

其余变体（after/equivalent-01/before 等）保留在各自 CVE 组内作对照，不计入对应类别数量。

## 候选池（待筛，不设数量）

| 函数 | pair_id | 补丁形态 | 状态 |
|---|---|---|---|
| i40e_vc_config_queues_msg | pairvul:CWE-20:1880 | `if (idx >= ARRAY_SIZE(vf->ch))` | 待筛 |
| kvm_vm_ioctl_create_vcpu | pairvul:CWE-20:332 | `if (id >= KVM_MAX_VCPUS)` | 待筛 |
| console_unlock | pairvul:CWE-119:171 | `if (len+1 >= sizeof(text))` | 待筛 |
| xdr_set_page_base | pairvul:CWE-119:3075 | `if (base >= maxlen)` | 待筛 |
| vfio_pci_ioctl | pairvul:CWE-119:1137 | `if (hdr.start >= max \|\| hdr.start + hdr.count > max)` | 待筛 |
| ll_free_user_pages | pairvul:CWE-787:2409 | — | 待筛 |
| nf_ct_frag6_gather | pairvul:CWE-787:1162 | — | 待筛 |
| x509_decode_time | pairvul:CWE-125:776 | — | 待筛 |
| put_chars | pairvul:CWE-787:1541 | — | 待筛 |

## 待办

1. get_pipe（1349）源码提交 hash 与重放证据复核。
2. `code_sha256` 联表口径：统一到原始测试集代码片段 hash，同时保留抽取函数文件 hash + 原函数名/改名后函数名。
3. `results/` 是否入库：先核对其中是否含运行环境信息。

完整机器可读版见 `candidates.json`。
