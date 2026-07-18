---
name: agentscope-v1-discovery-and-api-mapping
description: When trying to use AgentScope and the documentation describes v2.0 APIs that don't match the installed version, probe the actual installed version and map v2.0 concepts to v1.x APIs using inspect.signature and runtime introspection.
source: auto-skill
extracted_at: '2026-07-17T09:50:43.458Z'
---

# AgentScope Version Discovery and v1.x API Mapping

## Problem

AgentScope 2.0 documentation is readily available online and describes modern APIs (`Agent(...)`, `Toolkit(tools=[...])`, `PermissionContext`, `ContextConfig`). However, `pip install agentscope` installs v1.0.x, which has a completely different API surface. Using v2.0 patterns against v1.0 silently fails (e.g., `temperature` passed as a keyword argument is silently ignored with a warning).

## Approach

### Step 1: Verify the installed version

```bash
pip show agentscope
# or
python -c "import agentscope; print(agentscope.__version__)"
```

**Key finding**: v1.0.19 installed via `pip install agentscope`, while docs.agentscope.io documents v2.0.5dev. These are breaking-change versions.

### Step 2: Probe the actual API surface

Use `inspect.signature` and `dir()` to discover what's actually available:

```python
from agentscope.agent import ReActAgent
import inspect
sig = inspect.signature(ReActAgent.__init__)
# Inspect each parameter's name, type, and default
```

### Step 3: Map v2.0 concepts to v1.0 APIs

| v2.0 Concept | v1.0 Equivalent | Notes |
|---|---|---|
| `Agent(...)` | `ReActAgent(...)` | Different class name |
| `system_prompt=` | `sys_prompt=` | Shorter parameter name |
| `Toolkit(tools=[...])` | `Toolkit()` + `.register_tool_function(fn)` | Tools registered post-construction |
| `ToolBase` / `ToolChunk` | Functions returning `ToolResponse(content=...)` | No base class needed |
| `PermissionContext` | `PermissionContext` (same) | API consistent across versions |
| `ContextConfig` / `offloader` | `InMemoryMemory()` / `compression_config` | Memory-based, not config-based |
| `Plan` tools (TaskCreate, etc.) | `PlanNotebook` | Notebook-based, not tool-based |
| `DeepSeekChatFormatter` | `DeepSeekChatFormatter()` | Same, but **required** parameter |
| `agent.reply(msg)` | `agent.reply(msg)` | Same method, different internals |

### Step 4: Watch for silently-ignored parameters

**Critical finding**: In v1.0, `OpenAIChatModel.__init__` has explicit parameters: `model_name`, `api_key`, `stream`, `client_kwargs`, `generate_kwargs`. Unknown kwargs are logged as a warning and **silently ignored**:

```python
# ❌ temperature silently dropped in v1.0:
OpenAIChatModel(model_name="...", temperature=0.7, ...)

# ✅ temperature must go in generate_kwargs:
OpenAIChatModel(model_name="...", generate_kwargs={"temperature": 0.7}, ...)
```

### Step 5: Verify tool registration format

In v1.0, `Toolkit.get_json_schemas()` returns `[{"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}]` — access tool names via `t["function"]["name"]`, not `t["name"]`.

## Why

AgentScope documentation and the pip-installable version are different major versions. Blindly following v2.0 docs leads to broken code, silently ignored parameters, and confusing errors. Runtime introspection is the only reliable way to map concepts between versions.

## How to apply

```text
Step 1: pip show agentscope → check version
Step 2: inspect.signature(ClassName.__init__) for every class you plan to use
Step 3: Build a v2→v1 mapping table before writing any code
Step 4: Test each constructor with print() verification before relying on it
```
