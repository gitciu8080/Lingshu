# 灵枢 Agent 会话数据统计报告

> 生成时间: 2026-08-25 14:00:22 (UTC+8)
> 数据源: `data/users.db` (SQLite) + `.TaskMemory/sessions/` (任务快照, 读取 612 个)

## 一、总体概览

| 指标 | 值 |
|---|---|
| 会话总数 | 503 |
| 用户数 | 9 (会话涉及 11 个 user_id, 其中 7 个已无对应用户记录) |
| 时间范围 | 2026-08-03 ~ 2026-08-24 |
| 消息总数 | 118542 |
| 工具调用总数 (tool_call_start) | 24526 |
| 工具调用未正常结束数 | 3 |
| 会话平均消息数 | 235 (中位 197) |
| 会话平均工具调用数 | 48.8 (中位 43) |
| 会话平均时长 (全部) | 均值 12621.2 分钟, 中位 13683.5 分钟, 范围 0.0~29259.8 分钟 |
| 会话平均时长 (仅已终结) | 均值 12190.9 分钟, 中位 12990.4 分钟, 范围 0.0~29023.7 分钟 |
| 成功会话带 flag 比例 | 202/206 (98.1%) |

## 二、状态与阶段分布

### 2.1 会话状态

| 状态 | 数量 | 占比 |
|---|---|---|
| active | 203 | 40.4% |
| completed | 201 | 40.0% |
| failed | 70 | 13.9% |
| cancelled | 29 | 5.8% |

### 2.2 最终阶段 (phase)

| 阶段 | 数量 | 占比 |
|---|---|---|
| completed | 201 | 40.0% |
| failed | 69 | 13.7% |
| recon | 62 | 12.3% |
| planning | 50 | 9.9% |
| analysis | 45 | 8.9% |
| post_exploitation | 38 | 7.6% |
| cancelled | 29 | 5.8% |
| exploitation | 9 | 1.8% |

## 三、成功率

### 3.1 整体成功率

| 口径 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|
| 全部会话 | 206 | 64 | 233 | 76.3% | 41.0% |

> 已终结 = success 有明确值 (0/1)；无结果 = success 为 NULL (含 active / cancelled / 异常中断)。

### 3.2 按题型 (category_decision.primary) 分任务类型成功率

| 题型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| unknown | 155 | 54 | 10 | 91 | 84.4% | 34.8% |
| ai-ml | 87 | 43 | 24 | 20 | 64.2% | 49.4% |
| web | 77 | 32 | 11 | 34 | 74.4% | 41.6% |
| pwn | 65 | 24 | 11 | 30 | 68.6% | 36.9% |
| forensics | 25 | 14 | 4 | 7 | 77.8% | 56.0% |
| reverse | 36 | 14 | 1 | 21 | 93.3% | 38.9% |
| crypto | 35 | 11 | 2 | 22 | 84.6% | 31.4% |
| misc | 18 | 10 | 0 | 8 | 100.0% | 55.6% |
| malware | 5 | 4 | 1 | 0 | 80.0% | 80.0% |

### 3.3 按目标类型成功率

| 目标类型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| local_file | 212 | 109 | 29 | 74 | 79.0% | 51.4% |
| network | 258 | 86 | 32 | 140 | 72.9% | 33.3% |
| web_url | 31 | 11 | 2 | 18 | 84.6% | 35.5% |
| mixed(网络+本地) | 1 | 0 | 0 | 1 | - | 0.0% |
| other | 1 | 0 | 1 | 0 | 0.0% | 0.0% |

### 3.4 按模型 (provider/model) 成功率

| 模型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| deepseek/Min | 295 | 168 | 27 | 100 | 86.2% | 56.9% |
| qwen/Min | 120 | 19 | 34 | 67 | 35.8% | 15.8% |
| opencode/Max | 29 | 9 | 0 | 20 | 100.0% | 31.0% |
| deepseek/Max | 39 | 8 | 2 | 29 | 80.0% | 20.5% |
| xiaomi/Min | 4 | 2 | 1 | 1 | 66.7% | 50.0% |
| qwen/Max | 4 | 0 | 0 | 4 | - | 0.0% |
| qwen/Low | 6 | 0 | 0 | 6 | - | 0.0% |
| opencode/Min | 4 | 0 | 0 | 4 | - | 0.0% |
| deepseek/Low | 2 | 0 | 0 | 2 | - | 0.0% |

### 3.5 按用户成功率

| 用户 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| admin | 401 | 173 | 33 | 195 | 84.0% | 43.1% |
| Qwen | 80 | 18 | 30 | 32 | 37.5% | 22.5% |
| user1 | 13 | 13 | 0 | 0 | 100.0% | 100.0% |
| yangyifeng | 2 | 2 | 0 | 0 | 100.0% | 100.0% |
| u5 | 1 | 0 | 0 | 1 | - | 0.0% |
| u6 | 1 | 0 | 0 | 1 | - | 0.0% |
| u7 | 1 | 0 | 0 | 1 | - | 0.0% |
| u8 | 1 | 0 | 0 | 1 | - | 0.0% |
| u9 | 1 | 0 | 0 | 1 | - | 0.0% |
| u10 | 1 | 0 | 0 | 1 | - | 0.0% |
| u11 | 1 | 0 | 1 | 0 | 0.0% | 0.0% |

### 3.6 按任务大类 (title 前缀) 成功率

| 任务大类 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| (未标注) | 115 | 54 | 9 | 52 | 85.7% | 47.0% |
| Web | 120 | 54 | 11 | 55 | 83.1% | 45.0% |
| AI | 59 | 26 | 23 | 10 | 53.1% | 44.1% |
| 二进制利用 | 51 | 23 | 10 | 18 | 69.7% | 45.1% |
| 逆向分析 | 31 | 15 | 1 | 15 | 93.8% | 48.4% |
| 数字取证 | 22 | 13 | 4 | 5 | 76.5% | 59.1% |
| 综合安全 | 13 | 9 | 0 | 4 | 100.0% | 69.2% |
| 密码分析 | 19 | 9 | 2 | 8 | 81.8% | 47.4% |
| 恶意代码分析 | 4 | 3 | 1 | 0 | 75.0% | 75.0% |
| 安全测试任务 | 67 | 0 | 3 | 64 | 0.0% | 0.0% |
| 网络安全 | 2 | 0 | 0 | 2 | - | 0.0% |

## 四、会话类型分布

### 4.1 题型判定分布 (category_decision.primary)

| 题型 | 会话数 | 占比 |
|---|---|---|
| unknown | 155 | 30.8% |
| ai-ml | 87 | 17.3% |
| web | 77 | 15.3% |
| pwn | 65 | 12.9% |
| reverse | 36 | 7.2% |
| crypto | 35 | 7.0% |
| forensics | 25 | 5.0% |
| misc | 18 | 3.6% |
| malware | 5 | 1.0% |

### 4.2 目标类型分布

| 目标类型 | 会话数 | 占比 |
|---|---|---|
| network | 258 | 51.3% |
| local_file | 212 | 42.1% |
| web_url | 31 | 6.2% |
| mixed(网络+本地) | 1 | 0.2% |
| other | 1 | 0.2% |

### 4.3 模型分布

| Provider/Model | 会话数 | 占比 |
|---|---|---|
| deepseek/Min | 295 | 58.6% |
| qwen/Min | 120 | 23.9% |
| deepseek/Max | 39 | 7.8% |
| opencode/Max | 29 | 5.8% |
| qwen/Low | 6 | 1.2% |
| qwen/Max | 4 | 0.8% |
| opencode/Min | 4 | 0.8% |
| xiaomi/Min | 4 | 0.8% |
| deepseek/Low | 2 | 0.4% |

### 4.4 用户分布

| 用户 | 会话数 | 占比 |
|---|---|---|
| admin | 401 | 79.7% |
| Qwen | 80 | 15.9% |
| user1 | 13 | 2.6% |
| yangyifeng | 2 | 0.4% |
| u5 | 1 | 0.2% |
| u6 | 1 | 0.2% |
| u7 | 1 | 0.2% |
| u8 | 1 | 0.2% |
| u9 | 1 | 0.2% |
| u10 | 1 | 0.2% |
| u11 | 1 | 0.2% |

### 4.5 每日会话创建量 (UTC+8)

| 日期 | 会话数 |
|---|---|
| 08-03 | 13 `████` |
| 08-04 | 5 `██` |
| 08-05 | 7 `██` |
| 08-07 | 6 `██` |
| 08-10 | 48 `████████████████` |
| 08-11 | 65 `██████████████████████` |
| 08-12 | 58 `████████████████████` |
| 08-13 | 60 `████████████████████` |
| 08-14 | 89 `██████████████████████████████` |
| 08-15 | 19 `██████` |
| 08-16 | 45 `███████████████` |
| 08-17 | 24 `████████` |
| 08-23 | 38 `█████████████` |
| 08-24 | 26 `█████████` |

## 五、工具调用统计

### 5.1 总量

| 指标 | 值 |
|---|---|
| tool_call_start 事件 | 24526 |
| tool_call_end 事件 | 24523 |
| 未配对 (start 无 end, 异常中断) | 3 |
| 每会话平均 | 48.8 次 |
| 每会话中位数 | 43 次 |
| 每会话分位 (P25/P75/P90) | 24/70/109 次 |
| 单会话最多 | 364 次 |

> 注意：历史记录中大部分 `tool_call_start` 的工具名曾因脱敏缺失（content 为空），当前数据源经回填后可识别 24526/24526 次（100.0%）。 5.2 节基于可识别子集统计；另 `update_plan` 与 `UpdatePlan` 为历史版本命名不一致的同一工具。

### 5.2 可识别工具名分布 (Top 30, 占全部调用的 100.0%)

| 工具 | 调用次数 | 占可识别比例 |
|---|---|---|
| `scoped_shell` | 12990 | 53.0% |
| `UpdatePlan` | 2776 | 11.3% |
| `AddPlan` | 2515 | 10.3% |
| `dispatch_attack` | 898 | 3.7% |
| `dispatch_recon` | 890 | 3.6% |
| `view_mission_state` | 369 | 1.5% |
| `QueryMemory` | 321 | 1.3% |
| `cve_search` | 317 | 1.3% |
| `mcp__IDA_Tool__decompile` | 314 | 1.3% |
| `request_exploitation_approval` | 306 | 1.2% |
| `SubmitPlan` | 267 | 1.1% |
| `submit_nss_flag` | 236 | 1.0% |
| `complete_mission` | 224 | 0.9% |
| `analysis` | 219 | 0.9% |
| `mcp__IDA_Tool__analyze_function` | 155 | 0.6% |
| `ListPlan` | 154 | 0.6% |
| `dispatch_reverse` | 151 | 0.6% |
| `mcp__IDA_Tool__disasm` | 124 | 0.5% |
| `update_plan` | 107 | 0.4% |
| `ida_open_binary` | 96 | 0.4% |
| `mcp__IDA_Tool__get_bytes` | 91 | 0.4% |
| `Skill` | 89 | 0.4% |
| `manage_hypothesis` | 84 | 0.3% |
| `intelpwn_analyze` | 81 | 0.3% |
| `parallel_scoped_shell` | 74 | 0.3% |
| `mcp__IDA_Tool__survey_binary` | 72 | 0.3% |
| `list_available_tools` | 61 | 0.2% |
| `mcp__IDA_Tool__idb_close` | 51 | 0.2% |
| `mcp__IDA_Tool__search_text` | 48 | 0.2% |
| `mcp__IDA_Tool__xrefs_to` | 46 | 0.2% |

### 5.3 按 Agent 角色

| Agent | 工具调用 | 全部消息 |
|---|---|---|
| Alex - 行动指挥专家 | 5411 | 20835 |
| Ethan - 网络侦察专家 | 2325 | 9921 |
| Iris - 文件分析专家 | 2293 | 9884 |
| Orchestrator | 1893 | 7818 |
| Ryan - 逆向程序专家 | 1827 | 7023 |
| Mike - WEB渗透专家 | 1552 | 7347 |
| Attack | 1401 | 7013 |
| Victor - 二进制利用专家 | 1355 | 6713 |
| Sophia - 战略规划专家 | 1335 | 5275 |
| NetworkRecon | 1161 | 4805 |
| Ada - AI安全专家 | 1057 | 5097 |
| ArtifactTriage | 623 | 2312 |
| Brain | 622 | 1856 |
| Nora - 漏洞研判专家 | 360 | 1821 |
| Ryan - 逆向利用专家 | 359 | 1776 |
| Taylor - 综合安全专家 | 287 | 1227 |
| Iris - 数字取证专家 | 270 | 1155 |
| Alice - 密码学安全专家 | 206 | 1007 |
| Reserve | 89 | 349 |
| Morgan - 恶意代码分析专家 | 56 | 285 |
| Mia - 对话总结与报告专家 | 36 | 921 |
| Alice - 密码分析专家 | 8 | 39 |

### 5.4 按任务阶段

| 阶段 | 工具调用 | 占比 |
|---|---|---|
| planning | 7324 | 29.9% |
| recon | 5786 | 23.6% |
| post_exploitation | 5377 | 21.9% |
| analysis | 4538 | 18.5% |
| exploitation | 1329 | 5.4% |
| completed | 144 | 0.6% |
| failed | 28 | 0.1% |

## 六、人工审批

| 指标 | 值 |
|---|---|
| 请求过利用审批的会话数 | 297 |
| approval_required 事件总数 | 310 |
| approval_resolved 事件总数 | 290 |
| 快照中 exploitation_approval 事件 | 344 |
| 审批通过 (事件级) | 339 (98.5%) |
| 审批拒绝 (事件级) | 5 (1.5%) |
| 至少一次批准的会话 | 339 |
| 最终被拒绝的会话 | 3 |
| 快照中 exploitation_approved=true 的会话 | 339 |

## 七、Flag 与提交

| 指标 | 值 |
|---|---|
| flag_found 事件 | 200 |
| 会话表含 flag 的会话 | 207 |
| nss_submit 事件 | 187 (正确 122, 错误 65) |
| report_ready 事件 | 157 |
| 会话表 summary 非空 | 268 |

## 八、其他事件统计 (session_messages.event_type)

| 事件类型 | 数量 |
|---|---|
| tool_call_start | 24526 |
| tool_call_end | 24523 |
| thinking_end | 14505 |
| thinking_start | 14251 |
| text_end | 11398 |
| text_start | 11159 |
| plan_updated | 5422 |
| target_info | 3437 |
| message | 3211 |
| phase_change | 1599 |
| expert_joined | 1249 |
|  | 536 |
| mission_start | 501 |
| mission_end | 431 |
| approval_required | 310 |
| approval_resolved | 290 |
| agent_acknowledged | 267 |
| flag_found | 200 |
| nss_submit | 187 |
| report_ready | 157 |
| steering_received | 150 |
| mission_cancelled | 116 |
| user_message | 62 |
| error | 50 |
| scope_updated | 5 |

## 九、错误与异常

| 含 error 事件的会话数 | 50 |
| error 事件总数 | 50 |

## 十、系统级动作统计 (TaskMemory 事件链)

| 动作 | 次数 |
|---|---|
| checkpoint | 4118 |
| plan_item_updated | 3296 |
| phase_transition | 2705 |
| action_started | 1854 |
| action_finished | 1854 |
| plan_item_added | 1806 |
| dispatch_attack | 970 |
| dispatch_recon | 946 |
| finding_added | 915 |
| attack_step_added | 709 |
| mission_created | 612 |
| plan_created | 531 |
| session_title_created | 416 |
| exploitation_approval | 344 |
| failed_path_added | 306 |
| hypothesis_updated | 286 |
| session_title_finalized | 247 |
| plan_batch_submitted | 247 |
| evidence_added | 228 |
| conversation_summarized | 226 |
| attempt_started | 203 |
| nss_submit | 200 |
| attempt_finished | 184 |
| fact_added | 173 |
| dispatch_reverse | 141 |
| rag_context_injected | 141 |
| plan_item_marked | 132 |
| rag_retrieved | 106 |
| tool_capability_snapshot | 94 |
| orchestrator_stopped_without_terminal_state | 65 |
| hypothesis_added | 63 |
| context_injected | 52 |
| recon_max_iters_exceeded | 47 |
| agent_capability_loaded | 46 |
| orchestrator_max_iters_exceeded | 43 |
| nss_submit_unavailable | 39 |
| category_reclassified | 39 |
| model_alias_resolved | 36 |
| category_reclassification_rejected | 33 |
| rag_skipped | 27 |
| budgets_configured | 27 |
| nss_submit_format_warning | 19 |
| attack_error_counted | 17 |
| slab_submit_unavailable | 15 |
| capability_preflight | 14 |
| reverse_max_iters_exceeded | 13 |
| scope_expansion | 11 |
| tool_budget_exhausted | 9 |
| slab_submit | 8 |
| experience_injected | 5 |
| plan_item_deleted | 5 |
| slab_submit_error | 4 |
| action_duplicate_blocked | 3 |
| model_guard_safe_shutdown | 2 |
| brain_category_review_rejected | 2 |
| brain_category_review_accepted | 1 |
| rag_cache_hit | 1 |
| initial_plan_submitted | 1 |
| network_targets_discovered | 1 |
| attack_duplicate_rejected | 1 |

---
*本报告由 `scripts/session_stats.py` 自动生成。*
