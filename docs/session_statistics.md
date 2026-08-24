# 灵枢 Agent 会话数据统计报告

> 生成时间: 2026-08-17 23:32:45 (UTC+8)
> 数据源: `data/users.db` (SQLite) + `.TaskMemory/sessions/` (任务快照, 读取 443 个)

## 一、总体概览

| 指标 | 值 |
|---|---|
| 会话总数 | 439 |
| 用户数 | 9 (会话涉及 11 个 user_id, 其中 7 个已无对应用户记录) |
| 时间范围 | 2026-08-03 ~ 2026-08-17 |
| 消息总数 | 106434 |
| 工具调用总数 (tool_call_start) | 22494 |
| 工具调用未正常结束数 | 2 |
| 会话平均消息数 | 241 (中位 201) |
| 会话平均工具调用数 | 51.2 (中位 45) |
| 会话平均时长 (全部) | 均值 18.0 分钟, 中位 6.9 分钟, 范围 0.0~441.0 分钟 |
| 会话平均时长 (仅已终结) | 均值 17.3 分钟, 中位 9.2 分钟, 范围 0.0~143.8 分钟 |
| 时长剔除 (负值/时区不一致) | 5 |
| 成功会话带 flag 比例 | 172/176 (97.7%) |

## 二、状态与阶段分布

### 2.1 会话状态

| 状态 | 数量 | 占比 |
|---|---|---|
| completed | 177 | 40.3% |
| failed | 130 | 29.6% |
| cancelled | 87 | 19.8% |
| active | 45 | 10.3% |

### 2.2 最终阶段 (phase)

| 阶段 | 数量 | 占比 |
|---|---|---|
| completed | 185 | 42.1% |
| failed | 101 | 23.0% |
| cancelled | 87 | 19.8% |
| post_exploitation | 19 | 4.3% |
| analysis | 17 | 3.9% |
| planning | 15 | 3.4% |
| recon | 12 | 2.7% |
| exploitation | 3 | 0.7% |

## 三、成功率

### 3.1 整体成功率

| 口径 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|
| 全部会话 | 176 | 69 | 194 | 71.8% | 40.1% |

> 已终结 = success 有明确值 (0/1)；无结果 = success 为 NULL (含 active / cancelled / 异常中断)。

### 3.2 按题型 (category_decision.primary) 分任务类型成功率

| 题型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| unknown | 151 | 48 | 22 | 81 | 68.6% | 31.8% |
| ai-ml | 87 | 39 | 23 | 25 | 62.9% | 44.8% |
| web | 71 | 29 | 10 | 32 | 74.4% | 40.8% |
| pwn | 51 | 19 | 10 | 22 | 65.5% | 37.3% |
| forensics | 13 | 12 | 0 | 1 | 100.0% | 92.3% |
| crypto | 35 | 10 | 2 | 23 | 83.3% | 28.6% |
| misc | 13 | 8 | 0 | 5 | 100.0% | 61.5% |
| reverse | 13 | 8 | 1 | 4 | 88.9% | 61.5% |
| malware | 5 | 3 | 1 | 1 | 75.0% | 60.0% |

### 3.3 按目标类型成功率

| 目标类型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| local_file | 161 | 91 | 23 | 47 | 79.8% | 56.5% |
| network | 245 | 74 | 36 | 135 | 67.3% | 30.2% |
| web_url | 31 | 11 | 9 | 11 | 55.0% | 35.5% |
| mixed(网络+本地) | 1 | 0 | 0 | 1 | - | 0.0% |
| other | 1 | 0 | 1 | 0 | 0.0% | 0.0% |

### 3.4 按模型 (provider/model) 成功率

| 模型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| deepseek/Min | 274 | 150 | 26 | 98 | 85.2% | 54.7% |
| qwen/Min | 120 | 17 | 40 | 63 | 29.8% | 14.2% |
| deepseek/Max | 27 | 7 | 2 | 18 | 77.8% | 25.9% |
| xiaomi/Min | 4 | 2 | 1 | 1 | 66.7% | 50.0% |
| qwen/Max | 4 | 0 | 0 | 4 | - | 0.0% |
| qwen/Low | 6 | 0 | 0 | 6 | - | 0.0% |
| opencode/Min | 4 | 0 | 0 | 4 | - | 0.0% |

### 3.5 按用户成功率

| 用户 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |
|---|---|---|---|---|---|---|
| admin | 337 | 145 | 38 | 154 | 79.2% | 43.0% |
| Qwen | 80 | 16 | 30 | 34 | 34.8% | 20.0% |
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
| (未标注) | 115 | 53 | 7 | 55 | 88.3% | 46.1% |
| Web | 114 | 45 | 13 | 56 | 77.6% | 39.5% |
| AI | 59 | 23 | 22 | 14 | 51.1% | 39.0% |
| 二进制利用 | 43 | 18 | 9 | 16 | 66.7% | 41.9% |
| 数字取证 | 11 | 11 | 0 | 0 | 100.0% | 100.0% |
| 逆向分析 | 15 | 9 | 1 | 5 | 90.0% | 60.0% |
| 密码分析 | 19 | 8 | 2 | 9 | 80.0% | 42.1% |
| 综合安全 | 9 | 7 | 0 | 2 | 100.0% | 77.8% |
| 恶意代码分析 | 4 | 2 | 1 | 1 | 66.7% | 50.0% |
| 安全测试任务 | 48 | 0 | 14 | 34 | 0.0% | 0.0% |
| 网络安全 | 2 | 0 | 0 | 2 | - | 0.0% |

## 四、会话类型分布

### 4.1 题型判定分布 (category_decision.primary)

| 题型 | 会话数 | 占比 |
|---|---|---|
| unknown | 151 | 34.4% |
| ai-ml | 87 | 19.8% |
| web | 71 | 16.2% |
| pwn | 51 | 11.6% |
| crypto | 35 | 8.0% |
| forensics | 13 | 3.0% |
| misc | 13 | 3.0% |
| reverse | 13 | 3.0% |
| malware | 5 | 1.1% |

### 4.2 目标类型分布

| 目标类型 | 会话数 | 占比 |
|---|---|---|
| network | 245 | 55.8% |
| local_file | 161 | 36.7% |
| web_url | 31 | 7.1% |
| mixed(网络+本地) | 1 | 0.2% |
| other | 1 | 0.2% |

### 4.3 模型分布

| Provider/Model | 会话数 | 占比 |
|---|---|---|
| deepseek/Min | 274 | 62.4% |
| qwen/Min | 120 | 27.3% |
| deepseek/Max | 27 | 6.2% |
| qwen/Low | 6 | 1.4% |
| qwen/Max | 4 | 0.9% |
| opencode/Min | 4 | 0.9% |
| xiaomi/Min | 4 | 0.9% |

### 4.4 用户分布

| 用户 | 会话数 | 占比 |
|---|---|---|
| admin | 337 | 76.8% |
| Qwen | 80 | 18.2% |
| user1 | 13 | 3.0% |
| yangyifeng | 2 | 0.5% |
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

## 五、工具调用统计

### 5.1 总量

| 指标 | 值 |
|---|---|
| tool_call_start 事件 | 22494 |
| tool_call_end 事件 | 22492 |
| 未配对 (start 无 end, 异常中断) | 2 |
| 每会话平均 | 51.2 次 |
| 每会话中位数 | 45 次 |
| 每会话分位 (P25/P75/P90) | 25/74/114 次 |
| 单会话最多 | 364 次 |

> 注意：历史记录中大部分 `tool_call_start` 的工具名曾因脱敏缺失（content 为空），当前数据源经回填后可识别 22494/22494 次（100.0%）。 5.2 节基于可识别子集统计；另 `update_plan` 与 `UpdatePlan` 为历史版本命名不一致的同一工具。

### 5.2 可识别工具名分布 (Top 30, 占全部调用的 100.0%)

| 工具 | 调用次数 | 占可识别比例 |
|---|---|---|
| `scoped_shell` | 12046 | 53.6% |
| `UpdatePlan` | 2500 | 11.1% |
| `AddPlan` | 2496 | 11.1% |
| `dispatch_attack` | 856 | 3.8% |
| `dispatch_recon` | 853 | 3.8% |
| `view_mission_state` | 345 | 1.5% |
| `cve_search` | 309 | 1.4% |
| `request_exploitation_approval` | 284 | 1.3% |
| `mcp__IDA_Tool__decompile` | 282 | 1.3% |
| `QueryMemory` | 256 | 1.1% |
| `submit_nss_flag` | 228 | 1.0% |
| `SubmitPlan` | 219 | 1.0% |
| `complete_mission` | 199 | 0.9% |
| `analysis` | 197 | 0.9% |
| `mcp__IDA_Tool__analyze_function` | 153 | 0.7% |
| `ListPlan` | 140 | 0.6% |
| `dispatch_reverse` | 130 | 0.6% |
| `mcp__IDA_Tool__disasm` | 109 | 0.5% |
| `update_plan` | 107 | 0.5% |
| `mcp__IDA_Tool__get_bytes` | 79 | 0.4% |
| `ida_open_binary` | 78 | 0.3% |
| `intelpwn_analyze` | 68 | 0.3% |
| `mcp__IDA_Tool__survey_binary` | 59 | 0.3% |
| `Skill` | 54 | 0.2% |
| `ocr_image` | 44 | 0.2% |
| `mcp__IDA_Tool__idb_close` | 43 | 0.2% |
| `mcp__IDA_Tool__xrefs_to` | 40 | 0.2% |
| `mcp__IDA_Tool__search_text` | 35 | 0.2% |
| `mcp__IDA_Tool__find_regex` | 31 | 0.1% |
| `mcp__IDA_Tool__lookup_funcs` | 22 | 0.1% |

### 5.3 按 Agent 角色

| Agent | 工具调用 | 全部消息 |
|---|---|---|
| Alex - 行动指挥专家 | 4823 | 18739 |
| Ethan - 网络侦察专家 | 2200 | 9436 |
| Orchestrator | 1893 | 7705 |
| Iris - 文件分析专家 | 1747 | 7473 |
| Ryan - 逆向程序专家 | 1547 | 6023 |
| Mike - WEB渗透专家 | 1515 | 7188 |
| Attack | 1401 | 7013 |
| Victor - 二进制利用专家 | 1308 | 6545 |
| Sophia - 战略规划专家 | 1287 | 4845 |
| NetworkRecon | 1161 | 4805 |
| Ada - AI安全专家 | 1057 | 5097 |
| ArtifactTriage | 623 | 2312 |
| Brain | 622 | 1856 |
| Ryan - 逆向利用专家 | 333 | 1690 |
| Nora - 漏洞研判专家 | 295 | 1515 |
| Alice - 密码学安全专家 | 206 | 1007 |
| Iris - 数字取证专家 | 165 | 700 |
| Taylor - 综合安全专家 | 157 | 792 |
| Reserve | 89 | 349 |
| Morgan - 恶意代码分析专家 | 56 | 285 |
| Alice - 密码分析专家 | 8 | 39 |
| Mia - 对话总结与报告专家 | 1 | 667 |

### 5.4 按任务阶段

| 阶段 | 工具调用 | 占比 |
|---|---|---|
| planning | 6927 | 30.8% |
| recon | 5461 | 24.3% |
| post_exploitation | 5105 | 22.7% |
| analysis | 3694 | 16.4% |
| exploitation | 1192 | 5.3% |
| completed | 100 | 0.4% |
| failed | 15 | 0.1% |

## 六、人工审批

| 指标 | 值 |
|---|---|
| 请求过利用审批的会话数 | 278 |
| approval_required 事件总数 | 288 |
| approval_resolved 事件总数 | 269 |
| 快照中 exploitation_approval 事件 | 272 |
| 审批通过 (事件级) | 267 (98.2%) |
| 审批拒绝 (事件级) | 5 (1.8%) |
| 至少一次批准的会话 | 267 |
| 最终被拒绝的会话 | 3 |
| 快照中 exploitation_approved=true 的会话 | 267 |

## 七、Flag 与提交

| 指标 | 值 |
|---|---|
| flag_found 事件 | 184 |
| 会话表含 flag 的会话 | 177 |
| nss_submit 事件 | 179 (正确 115, 错误 64) |
| report_ready 事件 | 133 |
| 会话表 summary 非空 | 225 |

## 八、其他事件统计 (session_messages.event_type)

| 事件类型 | 数量 |
|---|---|
| tool_call_start | 22494 |
| tool_call_end | 22492 |
| thinking_end | 13514 |
| thinking_start | 13259 |
| text_end | 10425 |
| text_start | 10185 |
| plan_updated | 5038 |
| message | 2896 |
| phase_change | 1407 |
| expert_joined | 1073 |
| target_info | 659 |
|  | 536 |
| mission_start | 439 |
| mission_end | 377 |
| approval_required | 288 |
| approval_resolved | 269 |
| agent_acknowledged | 265 |
| flag_found | 184 |
| nss_submit | 179 |
| steering_received | 149 |
| report_ready | 133 |
| mission_cancelled | 85 |
| error | 48 |
| user_message | 40 |

## 九、错误与异常

| 含 error 事件的会话数 | 48 |
| error 事件总数 | 48 |

## 十、系统级动作统计 (TaskMemory 事件链)

| 动作 | 次数 |
|---|---|
| plan_item_updated | 2537 |
| checkpoint | 2408 |
| phase_transition | 2130 |
| plan_item_added | 1794 |
| dispatch_recon | 812 |
| dispatch_attack | 800 |
| finding_added | 718 |
| attack_step_added | 582 |
| mission_created | 443 |
| plan_created | 395 |
| session_title_created | 280 |
| exploitation_approval | 272 |
| session_title_finalized | 181 |
| nss_submit | 179 |
| conversation_summarized | 139 |
| plan_item_marked | 132 |
| plan_batch_submitted | 123 |
| dispatch_reverse | 113 |
| orchestrator_stopped_without_terminal_state | 48 |
| recon_max_iters_exceeded | 44 |
| orchestrator_max_iters_exceeded | 41 |
| model_alias_resolved | 35 |
| nss_submit_unavailable | 30 |
| context_injected | 21 |
| nss_submit_format_warning | 19 |
| reverse_max_iters_exceeded | 12 |
| attack_error_counted | 12 |
| scope_expansion | 6 |
| plan_item_deleted | 5 |
| model_guard_safe_shutdown | 2 |
| attack_duplicate_rejected | 1 |

---
*本报告由 `scripts/session_stats.py` 自动生成。*
