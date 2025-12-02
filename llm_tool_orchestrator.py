"""
LLM Tool Orchestrator

This module enables the LLM to autonomously:
1. Discover available security tools
2. Select appropriate tools based on user intent
3. Chain tools together intelligently
4. Aggregate and synthesize results

Inspired by OSINT tool aggregation patterns with LLM-driven orchestration.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from tools.tool_registry import (
    get_tool_registry,
    ToolRegistry,
    ToolMetadata,
    InputType
)


@dataclass
class ToolExecutionResult:
    """Result of executing a single tool."""
    tool_name: str
    success: bool
    output: Dict[str, Any]
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class OrchestrationPlan:
    """
    Plan for executing multiple tools.

    The LLM generates this plan based on the user's request.
    """
    tools: List[str]  # Tool names in execution order
    reasoning: str  # Why these tools were selected
    expected_flow: str  # Description of how data flows between tools
    parallel_groups: List[List[str]] = None  # Tools that can run in parallel


class LLMToolOrchestrator:
    """
    Orchestrates security tool execution based on LLM decisions.

    The LLM:
    1. Analyzes user request
    2. Queries tool registry
    3. Selects appropriate tools
    4. Determines execution order
    5. Chains tool outputs
    6. Synthesizes final report
    """

    def __init__(self, llm_client=None):
        """
        Initialize orchestrator.

        Args:
            llm_client: LLM client (Ollama, OpenAI, etc.) for autonomous decisions
        """
        self.registry: ToolRegistry = get_tool_registry()
        self.llm_client = llm_client
        self.execution_history: List[ToolExecutionResult] = []

    def get_tool_catalog_for_llm(self) -> str:
        """
        Get formatted tool catalog for LLM context.

        Returns:
            Markdown-formatted catalog of all available tools
        """
        return self.registry.get_llm_tool_catalog()

    def suggest_tools_for_input(self, input_value: str, input_type: InputType) -> List[ToolMetadata]:
        """
        Suggest tools based on input type.

        Args:
            input_value: The actual input value
            input_type: Type of input (IP, domain, email, etc.)

        Returns:
            List of recommended tools
        """
        # Get tools that accept this input type
        tools = self.registry.list_by_input_type(input_type)

        # Filter out disabled/deprecated tools
        tools = [t for t in tools if t.enabled and not t.deprecated]

        # Sort by safety (safe tools first, then intrusive)
        tools.sort(key=lambda t: (not t.is_safe, t.is_intrusive))

        return tools

    def suggest_tool_chain(self, start_tool: str) -> List[str]:
        """
        Suggest a chain of tools starting from a tool.

        Args:
            start_tool: Starting tool name

        Returns:
            Ordered list of tool names
        """
        return self.registry.get_tool_chain(start_tool)

    def execute_tool(self, tool_name: str, **kwargs) -> ToolExecutionResult:
        """
        Execute a single tool by name.

        Args:
            tool_name: Name of tool to execute
            **kwargs: Parameters for the tool

        Returns:
            Execution result
        """
        import time

        tool = self.registry.get_tool(tool_name)
        if not tool:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                output={},
                error=f"Tool '{tool_name}' not found in registry"
            )

        # Get the actual function
        func = self.registry.get_function(tool.function_name)
        if not func:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                output={},
                error=f"Function '{tool.function_name}' not registered"
            )

        # Validate parameters
        required_params = [p.name for p in tool.parameters if p.required]
        missing = [p for p in required_params if p not in kwargs]
        if missing:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                output={},
                error=f"Missing required parameters: {', '.join(missing)}"
            )

        # Execute tool
        try:
            start_time = time.time()
            result = func(**kwargs)
            duration = time.time() - start_time

            exec_result = ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                output=result,
                duration=duration
            )

            self.execution_history.append(exec_result)
            return exec_result

        except Exception as e:
            exec_result = ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                output={},
                error=str(e)
            )

            self.execution_history.append(exec_result)
            return exec_result

    def execute_tool_chain(self, plan: OrchestrationPlan, initial_data: Dict[str, Any]) -> List[ToolExecutionResult]:
        """
        Execute a chain of tools according to plan.

        Args:
            plan: Orchestration plan from LLM
            initial_data: Initial input data

        Returns:
            List of execution results
        """
        results = []
        context = initial_data.copy()

        for tool_name in plan.tools:
            tool = self.registry.get_tool(tool_name)
            if not tool:
                print(f"[WARNING] Tool '{tool_name}' not found, skipping")
                continue

            # Extract parameters from context
            params = {}
            for param in tool.parameters:
                if param.name in context:
                    params[param.name] = context[param.name]
                elif not param.required and param.default is not None:
                    params[param.name] = param.default

            # Execute tool
            print(f"[EXECUTING] {tool_name} with params: {list(params.keys())}")
            result = self.execute_tool(tool_name, **params)
            results.append(result)

            # Update context with output for chaining
            if result.success:
                context.update(result.output)
                print(f"[SUCCESS] {tool_name} completed in {result.duration:.2f}s")
            else:
                print(f"[ERROR] {tool_name} failed: {result.error}")
                # Continue with next tool (graceful degradation)

        return results

    def generate_llm_tool_selection_prompt(self, user_request: str, available_data: Dict[str, Any]) -> str:
        """
        Generate prompt for LLM to select tools.

        Args:
            user_request: User's natural language request
            available_data: Available input data (IP, domain, etc.)

        Returns:
            Formatted prompt for LLM
        """
        tool_catalog = self.get_tool_catalog_for_llm()

        prompt = f"""You are an expert cybersecurity analyst with access to a suite of security scanning tools.

USER REQUEST: {user_request}

AVAILABLE INPUT DATA:
{json.dumps(available_data, indent=2)}

{tool_catalog}

YOUR TASK:
1. Analyze the user's request and available input data
2. Select the most appropriate security tools from the catalog above
3. Determine the optimal execution order (consider tool prerequisites and chains)
4. Explain your reasoning for each tool selection

IMPORTANT RULES:
- Only select tools that are relevant to the request
- Consider tool prerequisites (e.g., "Nmap Service Detection" should follow "Nmap Quick Scan")
- Chain tools logically (e.g., DNS Resolution → Port Scan → Service Detection → Vuln Scan)
- Avoid redundant tools (don't run multiple port scanners unless comparing)
- Consider safety: prefer passive tools when possible, use intrusive tools only when necessary
- If API keys are required, mention it

OUTPUT FORMAT (JSON):
{{
    "selected_tools": [
        {{
            "tool_name": "Tool Name",
            "function_name": "function_name",
            "purpose": "Why this tool is needed",
            "parameters": {{"param_name": "value or source"}},
            "expected_output": "What information this tool will provide"
        }}
    ],
    "execution_order": ["tool1", "tool2", "tool3"],
    "reasoning": "Overall strategy explanation",
    "estimated_duration": "e.g., 5-10 minutes",
    "warnings": ["Any warnings about intrusive scans, authorization needs, etc."]
}}

Provide your tool selection and orchestration plan:"""

        return prompt

    def generate_llm_synthesis_prompt(self, results: List[ToolExecutionResult], user_request: str) -> str:
        """
        Generate prompt for LLM to synthesize results.

        Args:
            results: Tool execution results
            user_request: Original user request

        Returns:
            Formatted prompt for LLM
        """
        # Format results for LLM
        formatted_results = []
        for result in results:
            formatted_results.append({
                "tool": result.tool_name,
                "success": result.success,
                "output": result.output if result.success else None,
                "error": result.error,
                "duration": f"{result.duration:.2f}s"
            })

        prompt = f"""You are a senior cybersecurity analyst synthesizing results from multiple security scanning tools.

ORIGINAL REQUEST: {user_request}

TOOL EXECUTION RESULTS:
{json.dumps(formatted_results, indent=2)}

YOUR TASK:
Analyze the aggregated tool results and provide a comprehensive security analysis report.

REPORT STRUCTURE:
1. **Executive Summary**: High-level findings and risk assessment
2. **Detailed Findings**: Organize by category (network, vulnerabilities, threat intelligence, etc.)
3. **Attack Surface Analysis**: What is exposed and accessible?
4. **Risk Assessment**: Critical, high, medium, low findings with CVSS scores if available
5. **Threat Intelligence**: Any known vulnerabilities, malware, breaches, or malicious activity
6. **Recommendations**: Prioritized action items for remediation

IMPORTANT:
- Correlate findings across multiple tools (e.g., open ports from nmap + vulnerabilities from shodan)
- Identify patterns and anomalies
- Be specific about risks and impacts
- Provide actionable recommendations
- Highlight critical findings prominently
- If tools failed, note what data is missing and suggest alternatives

Generate your comprehensive security analysis report:"""

        return prompt

    def get_execution_summary(self) -> Dict[str, Any]:
        """
        Get summary of all tool executions in this session.

        Returns:
            Summary statistics
        """
        total = len(self.execution_history)
        successful = sum(1 for r in self.execution_history if r.success)
        failed = total - successful
        total_duration = sum(r.duration for r in self.execution_history)

        return {
            "total_tools_executed": total,
            "successful": successful,
            "failed": failed,
            "total_duration_seconds": round(total_duration, 2),
            "tools_used": [r.tool_name for r in self.execution_history],
            "failed_tools": [r.tool_name for r in self.execution_history if not r.success]
        }


def create_orchestration_plan_from_llm_response(llm_response: Dict[str, Any]) -> OrchestrationPlan:
    """
    Parse LLM response into orchestration plan.

    Args:
        llm_response: JSON response from LLM with tool selection

    Returns:
        Orchestration plan
    """
    return OrchestrationPlan(
        tools=llm_response.get("execution_order", []),
        reasoning=llm_response.get("reasoning", ""),
        expected_flow=" → ".join(llm_response.get("execution_order", []))
    )


# Example usage
if __name__ == "__main__":
    # Initialize orchestrator
    orchestrator = LLMToolOrchestrator()

    # Example 1: Get tool catalog
    print("=== TOOL CATALOG ===")
    print(orchestrator.get_tool_catalog_for_llm()[:500] + "...")

    # Example 2: Suggest tools for IP address
    print("\n=== TOOLS FOR IP ADDRESS ===")
    tools = orchestrator.suggest_tools_for_input("8.8.8.8", InputType.IP_ADDRESS)
    for tool in tools[:5]:
        print(f"- {tool.name}: {tool.description}")

    # Example 3: Suggest tool chain
    print("\n=== TOOL CHAIN STARTING FROM 'Nmap Quick Scan' ===")
    chain = orchestrator.suggest_tool_chain("Nmap Quick Scan")
    print(" → ".join(chain))

    # Example 4: Generate LLM prompt
    print("\n=== LLM TOOL SELECTION PROMPT ===")
    prompt = orchestrator.generate_llm_tool_selection_prompt(
        user_request="Scan example.com for vulnerabilities",
        available_data={"domain": "example.com"}
    )
    print(prompt[:500] + "...")
