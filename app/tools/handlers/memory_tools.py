"""
Memory Tool Handlers
====================

Handles: read_memory, write_memory, forget_memory, summarize_target, clear_memory, show_results
"""
from typing import Dict, Any
from app.tools.handlers import register_handler


@register_handler("read_memory")
def handle_read_memory(action_input: Dict[str, Any], state: Any) -> str:
    """Search archival memory for past findings."""
    query = action_input.get("query", "")
    if not query:
        return 'Error: No query specified. Example: read_memory with {"query": "snode.com ports"}'
    
    print(f"  🧠 Searching memory for: {query}...")
    
    from app.agent.memory import MemoryManager, AttackMemory
    memory = AttackMemory(persist=True)
    manager = MemoryManager(memory)
    
    return manager.read_memory(query)


@register_handler("write_memory")
def handle_write_memory(action_input: Dict[str, Any], state: Any) -> str:
    """Store facts to long-term memory."""
    fact_type = action_input.get("fact_type", "note")
    target = action_input.get("target", "")
    data = action_input.get("data", {})
    
    if not target:
        return 'Error: Target is required. Example: write_memory with {"fact_type": "note", "target": "domain.com", "data": {"note": "..."}}'
    
    print(f"  🧠 Writing to memory: [{fact_type}] {target}...")
    
    from app.agent.memory import MemoryManager, AttackMemory
    memory = AttackMemory(persist=True)
    manager = MemoryManager(memory)
    
    return manager.write_memory(fact_type, target, data, source="agent")


@register_handler("forget_memory")
def handle_forget_memory(action_input: Dict[str, Any], state: Any) -> str:
    """Remove facts from memory."""
    fact_id = action_input.get("fact_id", "")
    if not fact_id:
        return 'Error: fact_id is required. Example: forget_memory with {"fact_id": "abc123"}'
    
    print(f"  🧠 Forgetting memory: {fact_id}...")
    
    from app.agent.memory import MemoryManager, AttackMemory
    memory = AttackMemory(persist=True)
    manager = MemoryManager(memory)
    
    return manager.forget_memory(fact_id)


@register_handler("summarize_target")
def handle_summarize_target(action_input: Dict[str, Any], state: Any) -> str:
    """Get comprehensive summary of a target."""
    domain = action_input.get("domain", "")
    if not domain:
        return 'Error: Domain is required. Example: summarize_target with {"domain": "snode.com"}'
    
    print(f"  🧠 Summarizing target: {domain}...")
    
    from app.agent.memory import MemoryManager, AttackMemory
    memory = AttackMemory(persist=True)
    manager = MemoryManager(memory)
    
    return manager.summarize_target(domain)


@register_handler("clear_memory")
def handle_clear_memory(action_input: Dict[str, Any], state: Any) -> str:
    """Clear stored facts."""
    domain = action_input.get("domain", "")
    
    from app.agent.memory import AttackMemory
    memory = AttackMemory(persist=True)
    
    if domain:
        original_count = len(memory.facts)
        memory.facts = [f for f in memory.facts if domain not in f.target]
        removed = original_count - len(memory.facts)
        memory._save_facts()
        print(f"  🧹 Cleared {removed} facts for {domain}")
        return f"✅ Cleared {removed} facts related to {domain}. {len(memory.facts)} facts remaining."
    else:
        count = len(memory.facts)
        memory.clear_all()
        print(f"  🧹 Cleared all {count} facts")
        return f"✅ Cleared all {count} facts. Memory is now empty."


@register_handler("show_results")
def handle_show_results(action_input: Dict[str, Any], state: Any) -> str:
    """Show stored scan results."""
    from app.core.state import get_subdomain_file
    
    result_type = action_input.get("type", "all").lower()
    output = ""
    
    show_full = result_type in ["full", "all_subdomains", "full_list"]
    
    if result_type in ["subdomains", "all", "full", "all_subdomains", "full_list"]:
        subdomain_file = get_subdomain_file()
        if subdomain_file:
            with open(subdomain_file, 'r') as f:
                subs = [l.strip() for l in f if l.strip()]
            
            output += f"SUBDOMAINS ({len(subs)} total):\n"
            display_count = len(subs) if show_full else min(20, len(subs))
            for s in subs[:display_count]:
                output += f"  {s}\n"
            if len(subs) > display_count:
                output += f"  ... and {len(subs) - display_count} more\n"
    
    if result_type in ["ports", "all"]:
        port_results = state.context.get("port_scan_results", {})
        if port_results:
            output += f"\nPORTS ({len(port_results)} hosts):\n"
            for host, ports in list(port_results.items())[:10]:
                output += f"  {host}: {', '.join(map(str, ports))}\n"
    
    if result_type in ["httpx", "all"]:
        ok_hosts = state.context.get("httpx_200_hosts", [])
        forbidden = state.context.get("httpx_403_hosts", [])
        if ok_hosts or forbidden:
            output += f"\nHTTPX RESULTS:\n"
            output += f"  200 OK: {len(ok_hosts)} hosts\n"
            output += f"  403 Forbidden: {len(forbidden)} hosts\n"
    
    return output if output else "No results stored yet. Run some scans first."
