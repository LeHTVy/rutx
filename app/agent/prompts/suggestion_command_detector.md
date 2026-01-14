# Suggestion Command Detector

Detect if a user query is asking to execute a previously suggested tool/step.

## USER QUERY:
{query}

## CONTEXT:
{context_summary}
Suggested tools: {suggested_tools}

## CLASSIFICATION:

- **SUGGESTION_COMMAND**: User wants to execute a previously suggested tool or step
  * "next step"
  * "do the step"
  * "suggest step"
  * "do suggestion"
  * "as suggestion"
  * "your suggestion"
  * Any variation asking to proceed with a recommendation

- **NOT_SUGGESTION_COMMAND**: Regular query, not about executing suggestions
  * New requests
  * Direct commands
  * Questions
  * Other intents

## EXAMPLES:

SUGGESTION_COMMAND:
- "next step"
- "do the step"
- "suggest step"
- "do suggestion"
- "as suggestion"
- "your suggestion"
- "do the next step"
- "proceed with suggestion"

NOT_SUGGESTION_COMMAND:
- "scan example.com"
- "who are you"
- "yes"
- "run nmap"
- "what is XSS"

## OUTPUT:

Respond with ONLY one word: SUGGESTION_COMMAND or NOT_SUGGESTION_COMMAND
