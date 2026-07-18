---
name: agentscope-multi-agent-dispatch
description: In AgentScope 1.0, implement multi-agent orchestration by wrapping sub-agent calls as async tool functions registered on the Orchestrator's Toolkit, enabling a single ReActAgent to dispatch work to other agents via tool calls.
source: auto-skill
extracted_at: '2026-07-17T09:50:43.458Z'
---

# Multi-Agent Orchestration via Tool-Function Dispatch (AgentScope 1.0)

## Problem

AgentScope 1.0's `ReActAgent` has no built-in mechanism to call other agents. A common multi-agent architecture (e.g., Orchestrator → Recon → Attack) requires one agent to delegate work to others, but agents can only call tools, not other agents.

## Approach: Wrap sub-agent calls as tool functions

Create async functions that internally call `await sub_agent.reply()` and register them as tools on the Orchestrator's `Toolkit`.

### Pattern

```python
from agentscope.tool import Toolkit, ToolResponse
from agentscope.message import Msg

def create_orchestrator(model, recon_agent, attack_agent):
    """Factory that captures sub-agent references in tool closures."""

    async def dispatch_recon(target: str, focus: str = "全面扫描") -> ToolResponse:
        """Tool: dispatch Recon agent for info gathering."""
        msg = Msg(
            name="Orchestrator",
            content=f"请对目标 {target} 进行信息收集。重点：{focus}。",
            role="user",
        )
        result = await recon_agent.reply(msg)
        content = result.content if hasattr(result, "content") else str(result)
        return ToolResponse(content=f"[Recon 报告]\n\n{content}")

    async def dispatch_attack(target_info: str) -> ToolResponse:
        """Tool: dispatch Attack agent for exploitation."""
        msg = Msg(
            name="Orchestrator",
            content=f"请根据以下目标信息进行分析和攻击：\n\n{target_info}",
            role="user",
        )
        result = await attack_agent.reply(msg)
        content = result.content if hasattr(result, "content") else str(result)
        return ToolResponse(content=f"[Attack 报告]\n\n{content}")

    async def complete_mission(summary: str) -> ToolResponse:
        """Tool: mark mission complete and persist results."""
        save_to_memory(summary)
        return ToolResponse(content=f"[任务完成] {summary}")

    # Register as tools
    toolkit = Toolkit()
    toolkit.register_tool_function(dispatch_recon, func_name="dispatch_recon",
        func_description="派遣侦察兵对目标进行信息收集。")
    toolkit.register_tool_function(dispatch_attack, func_name="dispatch_attack",
        func_description="派遣攻击手分析漏洞并执行攻击。")
    toolkit.register_tool_function(complete_mission, func_name="complete_mission",
        func_description="完成任务并保存经验。")

    return ReActAgent(
        name="Orchestrator",
        sys_prompt=ORCHESTRATOR_PROMPT,  # tells it when to use which dispatch tool
        model=model,
        formatter=DeepSeekChatFormatter(),
        toolkit=toolkit,
        memory=InMemoryMemory(),
        plan_notebook=PlanNotebook(),  # shared with Brain for plan continuity
        max_iters=30,
    )
```

### Key details

1. **Tool functions must return `ToolResponse`**, not raw strings or AgentScope messages.
2. **Sub-agent results need extraction**: `result.content` may be a string or list of content blocks. Use `hasattr(result, "content")` to handle both.
3. **Tool function descriptions matter**: The Orchestrator's LLM uses these descriptions to decide when to dispatch. Be specific about what each dispatch does and when to use it.
4. **Context injection in the dispatch message**: The `Msg` sent to the sub-agent should include relevant context from the Orchestrator's current state. This is how information flows between agents.
5. **Error handling**: Wrap `await sub_agent.reply()` in try/except — sub-agent failures should not crash the Orchestrator's ReAct loop.

### Sharing PlanNotebook between agents

Brain (strategic planner) and Orchestrator (tactical executor) can share the same `PlanNotebook` instance:

```python
shared_plan = PlanNotebook()

brain = create_brain_agent(model)
brain.plan_notebook = shared_plan     # Brain creates the plan

orchestrator = create_orchestrator_agent(model, recon, attack)
orchestrator.plan_notebook = shared_plan  # Orchestrator reads and updates it
```

This enables the Orchestrator to call `finish_subtask()` on the same plan Brain created via `create_plan()`, maintaining a single source of truth for task state.

### Tool registration verification

Always verify tool registration after assembly:

```python
for t in orchestrator.toolkit.get_json_schemas():
    print(t["function"]["name"])  # v1.0 schema format
```

## Why

AgentScope 1.0's `ReActAgent.reply()` already implements a ReAct loop (reason → act → observe → reason). By making sub-agent calls look like tools, the Orchestrator's ReAct loop naturally handles:
- Deciding **when** to dispatch (based on system prompt + current state)
- Deciding **what context** to send (based on what the LLM passes as tool arguments)
- **Observing** results (the tool return value enters the agent's context)
- **Iterating** (after a dispatch result, the agent reasons about next steps)

This requires no custom loop — the entire orchestration is driven by the LLM's tool-calling decisions within a single `await orchestrator.reply()` call.

## How to apply

```text
Step 1: Create sub-agents (Recon, Attack) with their own toolkits
Step 2: Create async dispatch functions that call sub_agent.reply()
Step 3: Register dispatch functions as tools on Orchestrator's Toolkit
Step 4: Share PlanNotebook between Brain and Orchestrator
Step 5: Verify tool registration with get_json_schemas()
Step 6: Orchestrator.reply() naturally drives the full multi-agent workflow
```
