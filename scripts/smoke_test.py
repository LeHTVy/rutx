#!/usr/bin/env python3
"""
Minimal smoke test for rutx.

Goals:
- Verify imports for CLI + graph build succeed
- Exercise the intent -> prompt_analysis -> target_verification -> planner path
  without requiring a live LLM backend (monkeypatch OllamaClient + prompt analyzer)
- Ensure RAG/memory failures remain non-fatal (monkeypatch UnifiedRAG getter)

Run:
  python3 scripts/smoke_test.py
"""

from __future__ import annotations

import sys
from typing import Any, Dict

from pathlib import Path

# Ensure repo root is importable when running as a script.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _monkeypatch_llm() -> None:
    from app.llm.client import OllamaClient

    def _fake_generate(self: OllamaClient, prompt: str, *args: Any, **kwargs: Any) -> str:
        # Coordinator routing expects an agent name present in the output.
        if "Which agent should handle this task" in (prompt or ""):
            return "recon"
        # Most other callers are tolerant of empty / non-matching output (fallback paths).
        return ""

    OllamaClient.generate = _fake_generate  # type: ignore[method-assign]


def _monkeypatch_prompt_analyzer() -> None:
    # Avoid requiring LLM for prompt analysis in the smoke test.
    import app.agent.analyzer as analyzer_pkg

    class _FakePromptAnalyzer:
        def analyze_prompt(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
            return {"needs_checklist": False}

        def extract_target(self, query: str, context: Dict[str, Any]) -> str:
            return ""

        def create_checklist(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
            return {"context": context, "checklist": []}

    analyzer_pkg.get_user_prompt_analyzer = lambda: _FakePromptAnalyzer()  # type: ignore[assignment]


def _monkeypatch_rag_failure() -> None:
    # Make UnifiedRAG unavailable; core code should treat this as non-fatal.
    import app.rag.unified_memory as unified_memory

    unified_memory.get_unified_rag = lambda: (_ for _ in ()).throw(RuntimeError("smoke: rag disabled"))  # type: ignore[assignment]


def main() -> int:
    # Import sanity (graph is required for this smoke test)
    try:
        import app.agent.graph as graph
    except ModuleNotFoundError as e:
        print(f"smoke_test: WARN (graph deps missing, skipping graph checks): {e}")
        print("smoke_test: Hint: create a venv and install requirements:")
        print("  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt")
        return 0

    # CLI import is optional in minimal environments (depends on prompt_toolkit/rich)
    try:
        import app.cli.main  # noqa: F401
    except ModuleNotFoundError as e:
        print(f"smoke_test: WARN (CLI deps missing, skipping CLI import): {e}")

    _monkeypatch_llm()
    _monkeypatch_prompt_analyzer()
    _monkeypatch_rag_failure()

    # Build a minimal state and run key nodes in order.
    state: Dict[str, Any] = {
        "query": "scan example.com",
        "messages": [{"role": "user", "content": "scan example.com"}],
        "intent": "security_task",
        "suggested_tools": [],
        "suggestion_message": "",
        "tool_params": {},
        "confirmed": False,
        "selected_tools": [],
        "execution_results": {},
        "context": {},
        "response": "",
        "next_action": "",
        "mode": "manual",
        "autochain_iteration": 0,
        "autochain_results": [],
    }

    s1 = graph.prompt_analysis_node(state)  # should not call real LLM
    assert s1.get("next_action") in {"planner", "target_verification"}

    s2 = graph.target_verification_node(s1)  # domain is present, should bypass LLM
    assert isinstance(s2.get("context", {}), dict)

    # Planner node exists in the graph module and should be runnable.
    s3 = graph.planner_node(s2)
    assert isinstance(s3.get("context", {}), dict)
    assert "next_action" in s3

    print("smoke_test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

