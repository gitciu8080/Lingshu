"""Workflow wiring checks for artifact uploads that expose network targets.

These AST-only tests deliberately avoid importing runtime agent dependencies, so they
can run in a lightweight development environment as well as in the full stack.
"""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _module(path: str) -> ast.Module:
    return ast.parse((ROOT / path).read_text(encoding="utf-8"))


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )


def test_file_workflow_keeps_triage_for_first_pass_and_network_recon_for_orchestration() -> None:
    tree = _module("main.py")
    run_mission = _function(tree, "run_mission")

    assignments = [
        node
        for node in ast.walk(run_mission)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "initial_recon" for target in node.targets)
    ]
    assert any(
        isinstance(node.value, ast.Name) and node.value.id == "artifact_triage"
        for node in assignments
    )

    orchestrator_call = next(
        node
        for node in ast.walk(run_mission)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_orchestrator_agent"
    )
    keywords = {
        keyword.arg: keyword.value.id
        for keyword in orchestrator_call.keywords
        if keyword.arg is not None and isinstance(keyword.value, ast.Name)
    }
    assert keywords["recon_agent"] == "network_recon"
    assert keywords["artifact_triage_agent"] == "artifact_triage"


def test_orchestrator_exposes_separate_network_and_artifact_dispatch_tools() -> None:
    tree = _module("agent/Orchestrator.py")
    dispatch_recon = _function(tree, "dispatch_recon")
    dispatch_triage = _function(tree, "dispatch_artifact_triage")

    assert [arg.arg for arg in dispatch_recon.args.args][:2] == ["network_target", "focus"]
    assert dispatch_triage.args.args[0].arg == "focus"

    tool_targets = {
        call.args[0].id
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "AllowedFunctionTool"
        and call.args
        and isinstance(call.args[0], ast.Name)
    }
    assert {"dispatch_recon", "dispatch_artifact_triage"} <= tool_targets
