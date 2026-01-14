# Confirmation Detector

Detect if a user query is confirming a previous suggestion or action.

## USER QUERY:
{query}

## CONTEXT:
{context_summary}
Suggested tools: {suggested_tools}

## CLASSIFICATION:

- **CONFIRMATION**: User is confirming/approving a previous suggestion
  * Short confirmations: "yes", "y", "ok", "go", "run", "execute", "proceed"
  * Confirmations with tool selection: "yes nmap", "ok subfinder", "go with httpx"
  * Confirmations starting with: "yes", "ok", "let's", "lets", "go with"
  * Short queries (< 20 chars) when there are pending suggestions

- **NOT_CONFIRMATION**: Regular query, not a confirmation
  * New requests
  * Questions
  * Commands without context of previous suggestions
  * Long queries that are not confirmations

## EXAMPLES:

CONFIRMATION:
- "yes"
- "y"
- "ok"
- "go"
- "run"
- "execute"
- "proceed"
- "yes nmap"
- "ok subfinder"
- "let's do it"
- "go with httpx"

NOT_CONFIRMATION:
- "scan example.com"
- "who are you"
- "what is XSS"
- "yes but I want to scan all subdomains" (too long, has modification)
- "no"

## IMPORTANT RULES:

1. If query is exact match: "yes", "y", "ok", "go", "run", "execute", "proceed" → CONFIRMATION
2. If query starts with "yes", "ok", "let's", "lets", "go with" AND is short (< 20 chars) AND has pending suggestions → CONFIRMATION
3. If query contains tool name from suggested_tools → CONFIRMATION with tool selection
4. If query is "no", "n", "cancel", "stop", "abort" → NOT_CONFIRMATION (but should be handled as denial)

## OUTPUT:

Respond with ONLY one word: CONFIRMATION or NOT_CONFIRMATION
