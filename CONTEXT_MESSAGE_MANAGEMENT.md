## Context & Message Management (Current SNODE)

This document describes how SNODE stores, propagates, compresses, and persists **messages** and **context** in the current codebase.

### Scope

Covered:
- LangGraph per-turn state (`AgentState`)
- Volatile in-process session memory
- Persistent storage (PostgreSQL + ChromaDB)
- Topic-based history compression
- RAG indexing (UnifiedRAG)

---

## 1) Messages vs Context

- **Messages**: conversation turns (user/assistant) used for continuity and LLM prompting.
- **Context**: a structured dictionary of facts + control flags (target, findings, checklist state, tool history, etc.).

SNODE uses both:
- A message list for conversational continuity.
- A context dict for deterministic “facts/state” updated by tools and agents.

---

## 2) LangGraph Runtime State (per user turn)

State is defined in `app/agent/graph.py` as `AgentState`.

Key fields (high signal):
- `query`: current user input string
- `messages`: list of `{role, content}` pairs carried across turns
- `intent`: `security_task | confirm | question | memory_query`
- `context`: accumulated context dict (targets, findings, control flags)
- Planning output: `suggested_tools`, `suggested_commands`, `suggestion_message`
- Confirmation: `confirmed`, `selected_tools`
- Execution: `execution_results`
- Checklist: `checklist`, `current_task_id`, `checklist_complete`
- Autochain: `mode`, `autochain_iteration`, `autochain_results`

Important runtime behavior:
- A planning step often ends with a **suggestion** (planner returns `suggestion_message`); the next user turn is classified as `confirm` to continue.
- `context` is the primary accumulator used by later nodes (planner/executor/analyzer).

---

## 3) Volatile Session Memory (in-process)

### SessionMemory

Module: `app/memory/session.py`

SessionMemory provides:
- `AgentContext`: shared findings and tool tracking (domain, subdomains, ports, technologies, vulnerabilities, `tools_run`, etc.)
- `llm_messages`: a bounded list of recent messages used as lightweight LLM context

Retention:
- Recent message history is capped (keeps only the newest ~20 entries) to prevent context bloat.

This layer is **volatile** (lost on process exit).

---

## 4) Persistent Memory (cross-session)

### MemoryManager

Module: `app/memory/manager.py`

`MemoryManager.save_turn(...)` persists each conversational turn:
1) **PostgreSQL** (exact history)
   - stores both user and assistant messages
   - stores a context snapshot for session-level continuity
2) **Vector memory (ChromaDB)** (semantic recall)
   - stores assistant messages (and optionally user messages) as searchable documents with metadata
   - optional consolidation attempts to merge/replace redundant memories
3) **Topic-based history**
   - user messages start new topics; assistant messages append to the current topic
   - topics/bulks are saved back to PostgreSQL

### VectorMemory (ChromaDB)

Module: `app/memory/vector.py`

Key properties:
- Documents must be stored as **strings**; structured dict/list outputs are serialized to JSON text before insert.
- Metadata is normalized to ChromaDB-safe types.

---

## 5) Topic-based History Compression

Module: `app/memory/topics.py`

History structure:
- **Topic**: a group of related messages
- **Bulk**: summarized older topics
- **Current topic**: active topic kept in full detail

Compression strategy:
- Summarize older topics into bulks when token budgets are exceeded.
- Merge bulks to keep historical context compact.

Goal:
- keep the most relevant recent thread intact
- keep older work in compressed form

---

## 6) UnifiedRAG (Cross-session Recall + Tool Index)

Module: `app/rag/unified_memory.py`

UnifiedRAG maintains multiple collections (ChromaDB) for:
- tool/command semantic lookup (`tools_commands`)
- conversation recall (`conversations`)
- persistent findings (`session_findings`, plus supporting metadata indices)

During tool execution:
- raw tool outputs can be parsed into structured findings (hosts, ports, technologies, emails, CVEs, etc.)
- findings can be indexed into UnifiedRAG to improve future retrieval

This is distinct from `VectorMemory`:
- `VectorMemory`: general semantic “memory documents”
- `UnifiedRAG`: structured indices for tools and findings

---

## 7) Checklist-driven Context

Checklist tasks live in `context["checklist"]` as a list of task dicts (id, phase, required_tools, status, results, etc.).

Creation:
- `prompt_analysis_node` uses `UserPromptAnalyzer.create_checklist()`, which reuses `TaskBreakdownTool`.

Planning integration:
- Planner rewrites the working query to include the current task, e.g.:
  - `"<original query> - Task: <task.description>"`
- The active task id is stored in `context["current_task_id"]`.

---

## 8) Common Context Keys (Practical)

Typical keys in `context`:
- Targeting: `last_domain`, `target_domain`, `url_target`, `target_hint`
- Findings: `subdomains`, `subdomain_count`, `ips`, `open_ports`, `port_count`, `emails`, `detected_tech`
- Execution tracking: `tools_run`, `current_agent`
- Analyzer hints: `analyzer_next_tool`, `analyzer_next_reason`
- Checklist: `checklist`, `current_task_id`, `checklist_complete`, `task_required_tools`, `task_phase`

The context dict is not a strict schema; keys can evolve as agents/tools add new fields.

---

## 9) Practical Failure Modes

- **Vector documents must be text**: dict/list must be serialized before writing to ChromaDB.
- **Large tool outputs**: should be truncated/summarized before LLM parsing to avoid token blowups.
- **Checklist parse failure**: if the breakdown output cannot be parsed, the system falls back to a minimal checklist.

## Context & Message Management (Current SNODE)

This document explains how SNODE manages **messages** and **context** across a CLI session and across sessions.

It is written to match the current implementation (LangGraph state machine + session memory + persistent memory + RAG).

