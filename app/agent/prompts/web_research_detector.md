# Web Research Detector

Detect if a user question requires web research to get fresh/current information.

## USER QUESTION:
{query}

## CONTEXT:
{context_str}

## CLASSIFICATION:

- **NEEDS_RESEARCH**: Question requires fresh information from the web
  * Time-sensitive queries: "latest", "new", "recent", "2024", "2025", "2026"
  * How-to guides: "how to", "tutorial", "guide"
  * Exploitation techniques: "bypass", "exploit", "vulnerability", "cve-", "poc"
  * Explanations that may need current examples: "explain", "what is" (when asking about recent techniques)
  * Questions about current trends or recent vulnerabilities

- **NO_RESEARCH**: Question can be answered with general knowledge
  * Basic definitions: "what is XSS" (general knowledge)
  * System capabilities: "what can you do"
  * Identity questions: "who are you"
  * Questions that don't need current information

## EXAMPLES:

NEEDS_RESEARCH:
- "latest WAF bypass techniques in 2025"
- "how to exploit SQL injection"
- "explain CVE-2024-1234"
- "new vulnerability in WordPress 2025"
- "tutorial on XSS exploitation"
- "bypass techniques for authentication"

NO_RESEARCH:
- "what is XSS"
- "who are you"
- "what is SNODE"
- "what can you do"
- "explain SQL injection" (general explanation, not current techniques)

## OUTPUT:

Respond with ONLY one word: NEEDS_RESEARCH or NO_RESEARCH
