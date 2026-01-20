"""Main entry point for AI Pentest Agent."""

import sys
import uuid
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from agents.pentest_graph import PentestGraph
from rag.retriever import ConversationRetriever
from rag.results_storage import ToolResultsStorage
from ui.streaming_manager import StreamingManager
from utils.input_normalizer import InputNormalizer
from websearch.aggregator import SearchAggregator
from rich.prompt import Prompt
from api.conversation_api import ConversationAPI

console = Console()


def main():
    """Main entry point."""
    console.print(Panel.fit(
        "[bold cyan]AI Pentest Agent Multi-Model[/bold cyan]\n"
        "Ollama, AutoGen, LangGraph, LlamaIndex, RAG\n"
        "[dim]With Live Streaming & Typo Handling[/dim]",
        border_style="cyan"
    ))
    
    # Initialize components
    # Enable keyboard listener for expand/collapse (only if stdin is a terminal)
    enable_keyboard = sys.stdin.isatty() if hasattr(sys.stdin, 'isatty') else True
    streaming_manager = StreamingManager(console=console, enable_keyboard=enable_keyboard)
    search_aggregator = SearchAggregator()
    
    # Create interactive callback for asking user questions
    def ask_user_question(question: str) -> str:
        """Ask user a question and return their answer."""
        return Prompt.ask(f"\n[bold yellow]❓ {question}[/bold yellow]")
    
    # Initialize Qwen3 for semantic understanding in input normalizer
    from models.qwen3_agent import Qwen3Agent
    qwen3_agent = Qwen3Agent()
    
    input_normalizer = InputNormalizer(
        search_aggregator=search_aggregator,
        interactive_callback=ask_user_question,
        ai_model=qwen3_agent  # Enable AI-based semantic understanding
    )
    conversation_retriever = ConversationRetriever()
    results_storage = ToolResultsStorage()
    
    # Initialize memory manager and conversation API
    from memory.manager import get_memory_manager
    memory_manager = get_memory_manager()
    conversation_api = ConversationAPI(memory_manager=memory_manager)
    
    # Create streaming callback for graph
    def graph_stream_callback(event_type: str, event_name: str, event_data: any):
        """Handle streaming events from graph."""
        try:
            if event_type == "model_response":
                # Model response streaming
                panel_id = streaming_manager.create_model_panel(event_name)
                if isinstance(event_data, str):
                    streaming_manager.stream_model_response(panel_id, event_data)
            elif event_type == "tool_output":
                # Tool output streaming
                # event_name format: "tool_name" or "tool_name:command_name"
                parts = event_name.split(":", 1)
                tool_name = parts[0]
                command_name = parts[1] if len(parts) > 1 else None
                
                panel_id = streaming_manager.create_tool_panel(
                    tool_name=tool_name,
                    command_name=command_name
                )
                if isinstance(event_data, str):
                    streaming_manager.update_tool_output(panel_id, event_data)
            elif event_type == "state_update":
                # State update
                streaming_manager.update_progress(f"Node: {event_name}")
        except Exception as e:
            # Silently handle streaming errors to not break main flow
            pass
    
    graph = PentestGraph(stream_callback=graph_stream_callback)
    
    # Conversation management
    current_conversation_id: Optional[str] = None
    session_id: Optional[str] = None  # Legacy support
    
    # Show conversation selection menu
    console.print("\n[bold cyan]Conversation Management[/bold cyan]")
    console.print("1. Create new conversation")
    console.print("2. List existing conversations")
    console.print("3. Load existing conversation")
    console.print("4. Continue with new conversation (default)")
    
    choice = Prompt.ask("\n[dim]Choice (1-4, default: 4)[/dim]", default="4")
    
    if choice == "1":
        title = Prompt.ask("[dim]Conversation title (optional)[/dim]", default="")
        result = conversation_api.create_conversation(title=title if title else None)
        if result.get("success"):
            current_conversation_id = result["conversation_id"]
            console.print(f"[green]✅ Created conversation: {current_conversation_id}[/green]")
        else:
            console.print(f"[red]❌ Failed to create conversation: {result.get('error')}[/red]")
            current_conversation_id = memory_manager.start_conversation()
    elif choice == "2":
        result = conversation_api.list_conversations(limit=10)
        if result.get("success"):
            conversations = result["conversations"]
            if conversations:
                console.print("\n[bold]Existing conversations:[/bold]")
                for i, conv in enumerate(conversations, 1):
                    title = conv.get("title") or "Untitled"
                    conv_id = conv.get("id")
                    updated = conv.get("updated_at", "")[:10] if conv.get("updated_at") else ""
                    console.print(f"  {i}. {title} ({conv_id[:8]}...) - Updated: {updated}")
                
                load_choice = Prompt.ask("\n[dim]Load conversation number (or Enter to create new)[/dim]", default="")
                if load_choice.isdigit():
                    idx = int(load_choice) - 1
                    if 0 <= idx < len(conversations):
                        current_conversation_id = conversations[idx]["id"]
                        switch_result = conversation_api.switch_conversation(current_conversation_id, memory_manager)
                        if switch_result.get("success"):
                            console.print(f"[green]✅ Loaded conversation: {conversations[idx].get('title', 'Untitled')}[/green]")
                        else:
                            console.print(f"[red]❌ Failed to load conversation[/red]")
                            current_conversation_id = memory_manager.start_conversation()
                    else:
                        current_conversation_id = memory_manager.start_conversation()
                else:
                    current_conversation_id = memory_manager.start_conversation()
            else:
                console.print("[yellow]No existing conversations. Creating new...[/yellow]")
                current_conversation_id = memory_manager.start_conversation()
        else:
            console.print(f"[red]❌ Failed to list conversations[/red]")
            current_conversation_id = memory_manager.start_conversation()
    elif choice == "3":
        conv_id = Prompt.ask("[dim]Conversation ID[/dim]")
        if conv_id:
            switch_result = conversation_api.switch_conversation(conv_id, memory_manager)
            if switch_result.get("success"):
                current_conversation_id = conv_id
                console.print(f"[green]✅ Loaded conversation: {conv_id}[/green]")
            else:
                console.print(f"[red]❌ Failed to load conversation: {switch_result.get('error')}[/red]")
                current_conversation_id = memory_manager.start_conversation()
        else:
            current_conversation_id = memory_manager.start_conversation()
    else:
        # Default: Create new conversation
        current_conversation_id = memory_manager.start_conversation()
    
    # Get session_id for legacy compatibility
    session_id = memory_manager.session_id
    
    console.print(f"[dim]Conversation ID: {current_conversation_id}[/dim]")
    if session_id:
        console.print(f"[dim]Session ID (legacy): {session_id}[/dim]")
    console.print("")
    
    try:
        while True:
            # Get user input
            user_prompt = Prompt.ask("\n[bold green]You[/bold green]")
            
            if user_prompt.lower() in ["exit", "quit", "q"]:
                console.print("\n[cyan]Goodbye![/cyan]")
                break
            
            # Normalize input (fix typos, extract targets, verify DNS with web search)
            normalized = input_normalizer.normalize_input(user_prompt, verify_domains=True)
            normalized_prompt = normalized.get("normalized_text", user_prompt)
            
            # Show normalization if there were corrections
            corrections = []
            if normalized.get("corrected_tools"):
                for old, new in normalized["corrected_tools"].items():
                    corrections.append(f"Tool '{old}' → '{new}'")
            if normalized.get("corrected_targets"):
                for old, new in normalized["corrected_targets"].items():
                    corrections.append(f"Target '{old}' → '{new}' (verified via web search)")
            if normalized.get("normalized_targets"):
                for i, target in enumerate(normalized.get("targets", [])):
                    normalized_target = normalized["normalized_targets"][i]
                    if normalized_target != target and target not in normalized.get("corrected_targets", {}):
                        corrections.append(f"Target normalized: {target} → {normalized_target}")
            
            if corrections:
                console.print(f"[dim]Corrections: {', '.join(corrections)}[/dim]")
            
            # Check for special commands
            if user_prompt.lower().startswith("/"):
                cmd_parts = user_prompt[1:].split()
                cmd = cmd_parts[0].lower() if cmd_parts else ""
                
                if cmd == "list":
                    # List conversations
                    result = conversation_api.list_conversations(limit=20)
                    if result.get("success"):
                        conversations = result["conversations"]
                        console.print("\n[bold]Conversations:[/bold]")
                        for conv in conversations:
                            title = conv.get("title") or "Untitled"
                            conv_id = conv.get("id")
                            updated = conv.get("updated_at", "")[:19] if conv.get("updated_at") else ""
                            console.print(f"  • {title} - {conv_id[:8]}... - {updated}")
                    continue
                elif cmd == "switch" and len(cmd_parts) > 1:
                    # Switch conversation
                    conv_id = cmd_parts[1]
                    switch_result = conversation_api.switch_conversation(conv_id, memory_manager)
                    if switch_result.get("success"):
                        current_conversation_id = conv_id
                        session_id = memory_manager.session_id
                        console.print(f"[green]✅ Switched to conversation: {conv_id}[/green]")
                    else:
                        console.print(f"[red]❌ Failed to switch: {switch_result.get('error')}[/red]")
                    continue
                elif cmd == "new":
                    # Create new conversation
                    current_conversation_id = memory_manager.start_conversation()
                    session_id = memory_manager.session_id
                    console.print(f"[green]✅ Created new conversation: {current_conversation_id}[/green]")
                    continue
                elif cmd == "save":
                    # Save current conversation state
                    if current_conversation_id:
                        # State is already persisted, just confirm
                        console.print(f"[green]✅ Conversation state saved[/green]")
                    continue
                elif cmd == "help":
                    console.print("\n[bold]Commands:[/bold]")
                    console.print("  /list - List all conversations")
                    console.print("  /switch <id> - Switch to conversation")
                    console.print("  /new - Create new conversation")
                    console.print("  /save - Save current conversation")
                    console.print("  /help - Show this help")
                    continue
            
            # Add to persistent conversation buffer (production)
            if current_conversation_id:
                try:
                    memory_manager.conversation_store.add_message(current_conversation_id, "user", user_prompt)
                except Exception:
                    # Fallback to legacy
                    memory_manager.add_to_conversation_buffer(session_id, "user", user_prompt, conversation_id=current_conversation_id)
            else:
                # Legacy fallback
                memory_manager.add_to_conversation_buffer(session_id, "user", user_prompt)
            
            # Start streaming display
            streaming_manager.start()
            streaming_manager.clear()
            streaming_manager.set_total_steps(5)
            streaming_manager.update_progress("Starting workflow...")
            
            try:
                # Run graph with conversation_id
                result = graph.run_streaming(
                    user_prompt, 
                    session_id=session_id,  # Legacy support
                    conversation_id=current_conversation_id  # Production
                )
                
                # Get answer
                answer = result.get("answer", "No answer generated.")
                
                # Add to persistent conversation buffer (production)
                if current_conversation_id:
                    try:
                        memory_manager.conversation_store.add_message(current_conversation_id, "assistant", answer)
                        # Auto-compress if needed
                        memory_manager.summary_compressor.auto_compress_if_needed(current_conversation_id)
                    except Exception:
                        # Fallback to legacy
                        memory_manager.add_to_conversation_buffer(session_id, "assistant", answer, conversation_id=current_conversation_id)
                else:
                    # Legacy fallback
                    memory_manager.add_to_conversation_buffer(session_id, "assistant", answer)
                
                # Save conversation turn to memory manager (includes RAG, buffer, verified targets)
                try:
                    # Extract tools used from result
                    tools_used = []
                    tool_results = result.get("tool_results", [])
                    if tool_results:
                        tools_used = [tr.get("tool_name", "") for tr in tool_results if tr.get("tool_name")]
                    
                    # Extract verified target from result state if available
                    verified_target = None
                    result_state = result.get("state", {})
                    if result_state:
                        target_clarification = result_state.get("target_clarification", {})
                        verified_target = target_clarification.get("verified_domain")
                        if not verified_target:
                            session_context = result_state.get("session_context", {})
                            verified_target = session_context.get("target_domain")
                    
                    # Extract target from normalized input as fallback
                    if not verified_target:
                        extracted_targets = normalized.get("targets", [])
                        if extracted_targets:
                            verified_target = extracted_targets[0]
                    
                    memory_manager.save_turn(
                        user_message=user_prompt,
                        assistant_message=answer,
                        tools_used=tools_used,
                        session_id=session_id,  # Legacy
                        conversation_id=current_conversation_id,  # Production
                        context={"target_domain": verified_target}
                    )
                except Exception as e:
                    # Memory is optional, don't crash if it fails
                    import warnings
                    warnings.warn(f"Failed to save to memory: {str(e)}")
                
                # Complete progress
                streaming_manager.complete_progress_step("Workflow completed")
                
                # Stop streaming display
                streaming_manager.stop()
                
                # Display final answer
                console.print()  # New line
                console.print(Panel(
                    answer,
                    title="[bold blue]Final Answer[/bold blue]",
                    border_style="blue"
                ))
                
                # Show tool results if any
                tool_results = result.get("tool_results", [])
                if tool_results:
                    console.print(f"\n[dim]Executed {len(tool_results)} tool(s)[/dim]")
                    
            except Exception as e:
                streaming_manager.stop()
                raise e
    
    except KeyboardInterrupt:
        streaming_manager.stop()
        console.print("\n\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        streaming_manager.stop()
        console.print(f"\n[red]Error: {str(e)}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    main()
