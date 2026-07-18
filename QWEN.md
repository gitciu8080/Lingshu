# 安全智能体项目 (Security Agent Project)

## 项目概述

本项目是一个基于 **AgentScope** 框架构建的**多智能体网络安全攻防系统**。系统由多个专业化 Agent 协同工作，形成完整的"侦察→分析→攻击→后渗透"闭环流程。

## 系统架构

```
Brain (大脑)
    ↓
Orchestrator (总指挥)
    ↓
Recon (侦察) → Analysis (分析) → CVESearch (漏洞情报) → Attack (攻击)
    ↑                                                    ↓
    └──────────── Orchestrator 循环决策 ←─────────────────┘
```

### 核心 Agent

| Agent | 职责 | 阶段 |
|-------|------|------|
| `Brain` | 解析用户请求，制定初始作战计划 | 战略层 |
| `Orchestrator` | 持续运行的调度核心，根据任务状态决策下一步 | 战术层 |
| `Recon` | 浅层/深层信息收集（端口扫描、服务识别、目录扫描等） | 侦察阶段 |
| `Analysis` | 漏洞推理与分析 | 分析阶段 |
| `CVESearch` | 查询 CVE 漏洞情报、利用方式 | 分析阶段 |
| `Attack` | 执行漏洞利用、渗透攻击 | 攻击阶段 |

### 设计原则

> **所有 Agent 只负责"产生结果"，只有 Orchestrator 可以"改变任务状态"。**

- Recon / Attack / Analysis / CVESearch 只返回结果，不修改任务阶段
- 只有 Orchestrator 更新 Task Memory、推进状态、选择下一位 Agent
- 确保数据流**单向、可审计、可回放**

### 记忆系统

- **Task Memory**: 当前任务的状态档案（目标、计划、执行进度）
- **Agentic Memory**: 长期经验库（历史任务总结，供未来任务参考）

## 技术栈

- **Agent 框架**: [AgentScope](https://github.com/agentscope-ai/agentscope)
- **LLM**: DeepSeek (Flash/Pro) via OpenAI API
- **技能库**:
  - `Skills/ctf-skills/` — CTF 技能集合 (Git 子模块)
  - `Skills/cve-search/` — CVE 搜索工具 (Git 子模块)

## 目录结构

```
构想.md              # 完整系统设计文档（中文）
agent/
├── Brain.py         # 大脑：解析任务、制定计划
├── Orchestrator.py  # 总指挥：调度、决策循环
├── Recon.py         # 侦察：信息收集
├── Analysis.py      # 分析：漏洞推理
└── CVE_Search.py    # 漏洞情报：CVE 查询
LLM/
└── model.py         # LLM 模型封装 (DeepSeek)
Skills/
├── ctf-skills/      # CTF 技能 (Git 子模块)
└── cve-search/      # CVE 搜索 (Git 子模块)
```

## 当前状态

**设计阶段**。各 Agent 文件目前仅有注释框架，核心逻辑尚未实现。`构想.md` 包含了完整的系统设计和工作流描述。

## 运行与开发

> TODO: 项目目前处于设计阶段，尚未包含完整的入口脚本或依赖配置。
>
> 预计运行方式（待实现）：
> ```bash
> # 安装依赖
> pip install agentscope
> 
> # 运行智能体
> python main.py --target 10.8.21.128 --goal "获取 Flag"
> ```

## 开发约定

- 所有代码使用 **中文注释**
- Agent 职责单一，不越权修改任务状态
- Orchestrator 是唯一的决策中心
