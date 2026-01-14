# Customer Query Detector

Detect if a user question is asking about customers/clients who are using the system.

## USER QUESTION:
{query}

## CONTEXT:
{context_str}

## CLASSIFICATION:

- **CUSTOMER_QUERY**: User is asking about customers/clients
  * Questions about who is using the system: "who is using", "which customer", "ai đang sử dụng"
  * Questions about customer data: "khách hàng", "customer", "client", "khách hàng của tôi"
  * Questions about customer list: "customers", "clients", "trong số khách hàng"
  * Questions asking to identify or list customers

- **NOT_CUSTOMER_QUERY**: Regular question, not about customers
  * General questions about the system itself
  * Technical questions
  * Questions about features or capabilities
  * Any question that doesn't relate to customer/client information

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
