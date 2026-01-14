# Question Complexity Classifier

Classify whether a user question is SIMPLE or COMPLEX.

## USER QUESTION:
{query}

## CONTEXT:
{context_str}

## CLASSIFICATION:

- **SIMPLE**: Questions that can be answered quickly with basic knowledge
  * Identity questions: "who are you", "what are you", "what is SNODE"
  * Basic capability questions: "what can you do", "how do you work"
  * Simple explanations: "what is XSS", "what is SQL injection"
  * Questions that don't require deep reasoning or research
  * Typically 1-2 sentences, straightforward answers

- **COMPLEX**: Questions requiring deep analysis, research, or multi-step reasoning
  * Technical deep-dives: "explain how to bypass WAF", "how does CVE-2024-XXXX work"
  * Multi-part questions: "compare XSS vs CSRF and explain exploitation"
  * Questions requiring web research: "latest bypass techniques for 2025"
  * Questions about specific vulnerabilities with POC requests
  * Questions that need context from previous scans/results

## EXAMPLES:

SIMPLE:
- "who are you"
- "what is SNODE"
- "what can you do"
- "what is XSS"
- "tell me about yourself"

COMPLEX:
- "explain how to exploit SQL injection in detail with examples"
- "what are the latest WAF bypass techniques in 2025"
- "how does CVE-2024-1234 work and how can I exploit it"
- "compare XSS, CSRF, and SSRF vulnerabilities"
- "analyze the scan results and explain the vulnerabilities"

## OUTPUT:

Respond with ONLY one word: SIMPLE or COMPLEX
