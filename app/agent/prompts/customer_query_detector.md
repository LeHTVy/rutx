# Customer Query Detector

Detect if a user question is asking about customers/clients who are using the system.

## USER QUESTION:
{query}

## CONTEXT:
{context_str}

## CLASSIFICATION:

- **CUSTOMER_QUERY**: User is asking about customers/clients who are using the system
  * Questions about who is using the system: "who is using", "which customer", "ai đang sử dụng"
  * Questions about customer data: "khách hàng", "customer", "client", "khách hàng của tôi"
  * Questions about customer list: "customers", "clients", "trong số khách hàng"
  * Questions asking to identify or list customers
  * Questions asking "who is using this system" or "which customers are using SNODE"

- **NOT_CUSTOMER_QUERY**: Regular question, not about customers
  * Identity questions about the AI itself: "who are you", "what are you", "what is SNODE"
  * Questions about the system's capabilities: "what can you do", "how does this work"
  * Technical questions: "explain XSS", "what is SQL injection"
  * Questions about features or capabilities
  * Any question that doesn't relate to customer/client information

## CRITICAL RULES:

1. "who are you" → NOT_CUSTOMER_QUERY (asking about the AI, not customers)
2. "what are you" → NOT_CUSTOMER_QUERY (asking about the AI, not customers)
3. "who is using this" → CUSTOMER_QUERY (asking about customers using the system)
4. "which customer" → CUSTOMER_QUERY (asking about specific customer)
5. Identity questions about the AI itself are NEVER customer queries

## EXAMPLES:

CUSTOMER_QUERY:
- "who is using this"
- "which customer is using SNODE"
- "khách hàng của tôi"
- "ai đang sử dụng hệ thống"
- "show me customers"
- "list clients"

NOT_CUSTOMER_QUERY:
- "who are you"
- "what can you do"
- "what is SNODE"
- "how does this work"
- "explain XSS"

## OUTPUT:

Respond with ONLY one word: CUSTOMER_QUERY or NOT_CUSTOMER_QUERY
