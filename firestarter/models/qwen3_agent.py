"""Qwen3 agent for task analysis and breakdown."""

import ollama
import json
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from config import load_config
from tools.registry import get_registry


class Qwen3Agent:
    """Qwen3 agent for task analysis and breakdown."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize Qwen3 agent."""
        self.config = load_config(config_path) if config_path else self._load_default_config()
        self.model_config = self.config['models']['qwen3']
        self.ollama_base_url = self.config['ollama']['base_url']
        
        # Get tool registry to provide available tools information
        self.registry = get_registry()
        
        template_dir = Path(__file__).parent.parent / "prompts"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.system_prompt_template = self.env.get_template("qwen3_system.jinja2")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default config."""
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "ollama_config.yaml"
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def analyze_and_breakdown(self,
                             user_prompt: str,
                             conversation_history: Optional[str] = None,
                             tool_results: Optional[str] = None,
                             stream_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Analyze user prompt and breakdown into subtasks.
        
        Args:
            user_prompt: User prompt
            conversation_history: Conversation history
            tool_results: Previous tool results
            stream_callback: Optional callback for streaming response chunks
            
        Returns:
            Analysis result with subtasks
        """
        # Get available tools for the prompt
        # Show priority tools first, then by category relevance
        all_tools = self.registry.list_tools()
        priority_tools = [t for t in all_tools if t.priority]
        other_tools = [t for t in all_tools if not t.priority]
        
        # Combine: priority tools first, then others (limit to 150 total to avoid prompt bloat)
        tools_to_show = priority_tools + other_tools[:150-len(priority_tools)]
        
        # Format tools for display (name, description, category, assigned_agents)
        tools_summary = [
            {
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
                "assigned_agents": tool.assigned_agents,
                "commands": tool.list_commands() if tool.commands else [],
                "priority": tool.priority
            }
            for tool in tools_to_show
        ]
        
        # Also provide category-based tool lists for quick reference
        tools_by_category = {}
        for tool in all_tools:
            if tool.category not in tools_by_category:
                tools_by_category[tool.category] = []
            tools_by_category[tool.category].append(tool.name)
        
        system_prompt = self.system_prompt_template.render(
            conversation_history=conversation_history,
            tool_results=tool_results,
            available_tools=tools_summary,
            tools_by_category=tools_by_category
        )
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            if stream_callback:
                # Streaming mode
                content = ""
                response = ollama.chat(
                    model=self.model_config['model_name'],
                    messages=messages,
                    stream=True,
                    options={
                        "temperature": self.model_config.get('temperature', 0.7),
                        "top_p": self.model_config.get('top_p', 0.9),
                        "top_k": self.model_config.get('top_k', 40),
                        "num_predict": self.model_config.get('num_predict', 2048)
                    }
                )
                
                for chunk in response:
                    chunk_content = chunk.get('message', {}).get('content', '')
                    if chunk_content:
                        content += chunk_content
                        stream_callback(chunk_content)
            else:
                # Non-streaming mode
                response = ollama.chat(
                    model=self.model_config['model_name'],
                    messages=messages,
                    options={
                        "temperature": self.model_config.get('temperature', 0.7),
                        "top_p": self.model_config.get('top_p', 0.9),
                        "top_k": self.model_config.get('top_k', 40),
                        "num_predict": self.model_config.get('num_predict', 2048)
                    }
                )
                content = response.get('message', {}).get('content', '')
            
            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in content:
                    json_start = content.find("```json") + 7
                    json_end = content.find("```", json_start)
                    content = content[json_start:json_end].strip()
                elif "```" in content:
                    json_start = content.find("```") + 3
                    json_end = content.find("```", json_start)
                    content = content[json_start:json_end].strip()
                
                analysis = json.loads(content)
                return {
                    "success": True,
                    "analysis": analysis,
                    "raw_response": content
                }
            except json.JSONDecodeError:
                # Return raw response if JSON parsing fails
                return {
                    "success": True,
                    "analysis": {"raw_response": content},
                    "raw_response": content
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis": None
            }
