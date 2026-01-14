"""
Customer Query Tool

Handles queries about customers, technologies, and vulnerabilities.
Integrates with CustomerQuerySystem to query PostgreSQL and ChromaDB.
"""

import json
from typing import Dict, Any, Optional
from app.agent.tools.base import AgentTool
from app.rag.customer_query import get_customer_query_system
from app.ui import get_logger, format_findings

logger = get_logger()


class CustomerQueryTool(AgentTool):
    """Tool for querying customer data."""
    
    def execute(self, query: str = None, context: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """
        Execute customer query.
        
        Args:
            query: Natural language query
            context: Current context
            
        Returns:
            Dictionary with query results
        """
        if query is None and self.state:
            query = self.state.get("query", "")
        if context is None:
            context = self.state.get("context", {}) if self.state else {}
        
        if not query:
            return {
                "response": "Please provide a query about your customers.",
                "next_action": "end"
            }
        
        try:
            query_system = get_customer_query_system()
            
            # Execute natural language query
            logger.info(f"Querying customer data: {query[:100]}...")
            results = query_system.natural_language_query(query)
            
            if results.get("error"):
                return {
                    "response": f"Error querying customer data: {results.get('error')}",
                    "next_action": "end"
                }
            
            # Format results for display
            response_parts = []
            
            # Technology query results
            if "customers" in results:
                technology = results.get("technology", "Unknown")
                version = results.get("version")
                customers = results.get("customers", [])
                total = results.get("total_findings", 0)
                
                response_parts.append(f"## Query Results: {technology}")
                if version:
                    response_parts.append(f"**Version Filter:** {version}")
                response_parts.append(f"**Total Findings:** {total}")
                response_parts.append(f"**Customers Found:** {len(customers)}\n")
                
                if customers:
                    for customer in customers[:10]:  # Limit to 10
                        response_parts.append(f"### {customer.get('domain', 'Unknown Domain')}")
                        response_parts.append(f"- **Customer ID:** {customer.get('customer_id', 'N/A')}")
                        
                        if customer.get("versions"):
                            response_parts.append(f"- **Versions:** {', '.join(customer['versions'])}")
                        
                        if customer.get("findings_count"):
                            response_parts.append(f"- **Findings:** {customer['findings_count']}")
                        
                        response_parts.append("")
                else:
                    response_parts.append("No customers found matching the criteria.")
            
            # Vulnerability query results
            elif "affected_customers" in results:
                cve_id = results.get("cve_id")
                vulnerability = results.get("vulnerability")
                technology = results.get("technology")
                customers = results.get("affected_customers", [])
                cve_details = results.get("cve_details")
                
                response_parts.append("## Vulnerability Query Results")
                if cve_id:
                    response_parts.append(f"**CVE ID:** {cve_id}")
                if vulnerability:
                    response_parts.append(f"**Vulnerability:** {vulnerability}")
                if technology:
                    response_parts.append(f"**Technology:** {technology}")
                if cve_details:
                    response_parts.append(f"**CVE Description:** {cve_details.get('description', 'N/A')[:200]}")
                response_parts.append(f"**Affected Customers:** {len(customers)}\n")
                
                if customers:
                    for customer in customers[:10]:
                        response_parts.append(f"### {customer.get('domain', 'Unknown Domain')}")
                        response_parts.append(f"- **Customer ID:** {customer.get('customer_id', 'N/A')}")
                        if customer.get("findings"):
                            response_parts.append(f"- **Related Findings:** {len(customer['findings'])}")
                        response_parts.append("")
                else:
                    response_parts.append("No affected customers found.")
            
            # Customer findings query results
            elif "findings_by_type" in results:
                customer_id = results.get("customer_id")
                domain = results.get("domain")
                findings_by_type = results.get("findings_by_type", {})
                total = results.get("total_findings", 0)
                
                response_parts.append("## Customer Findings")
                if customer_id:
                    response_parts.append(f"**Customer ID:** {customer_id}")
                if domain:
                    response_parts.append(f"**Domain:** {domain}")
                response_parts.append(f"**Total Findings:** {total}\n")
                
                for ftype, findings in findings_by_type.items():
                    response_parts.append(f"### {ftype.upper()} ({len(findings)})")
                    for finding in findings[:5]:  # Limit to 5 per type
                        data = finding.get("data", {})
                        if isinstance(data, dict):
                            summary = json.dumps(data)[:150]
                        else:
                            summary = str(data)[:150]
                        response_parts.append(f"- {summary}...")
                    response_parts.append("")
            
            else:
                response_parts.append("No results found.")
            
            response = "\n".join(response_parts)
            
            return {
                "response": response,
                "context": context,
                "next_action": "end"
            }
        
        except Exception as e:
            logger.error(f"Customer query error: {e}")
            return {
                "response": f"Error executing customer query: {e}",
                "next_action": "end"
            }
