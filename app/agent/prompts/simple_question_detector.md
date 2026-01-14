# Simple Question Detector

Detect if a user query is a simple question that should be classified as QUESTION intent (not SECURITY_TASK).

## USER QUERY:
{query}

## CONTEXT:
{context_summary}
{domain_note}

## CLASSIFICATION:

- **SIMPLE_QUESTION**: Simple questions that don't require security tools
  * Identity questions: "who are you", "what are you", "what is SNODE"
  * Basic capability questions: "what can you do", "how do you work"
  * Simple explanations: "what is XSS", "what is SQL injection"
  * Questions starting with: who, what, where, when, why, how
  * Questions WITHOUT domain/IP addresses
  * Questions WITHOUT action verbs (scan, run, check, find, lookup, enumerate, exploit, attack, test)
  * Questions that can be answered with general knowledge, no tool execution needed

- **NOT_SIMPLE_QUESTION**: Queries that may need security tools or are not simple questions
  * Contains domain/IP addresses
  * Contains action verbs (scan, run, check, find, lookup, enumerate, exploit, attack, test)
  * Requests to perform security tasks
  * Commands or instructions

## EXAMPLES:

SIMPLE_QUESTION:
- "who are you"
- "what are you"
- "what is SNODE"
- "what can you do"
- "tell me about yourself"
- "what is XSS"
- "how does this work"
- "can you help me"

NOT_SIMPLE_QUESTION:
- "scan example.com"
- "who are you and scan example.com"
- "find subdomains for test.com"
- "check if port 80 is open"
- "run nmap on 192.168.1.1"
- "attack hellogroup"

## IMPORTANT RULES:

1. If query contains a domain/IP → NOT_SIMPLE_QUESTION (likely SECURITY_TASK)
2. If query contains action verbs → NOT_SIMPLE_QUESTION (likely SECURITY_TASK)
3. If query is just a question without targets/actions → SIMPLE_QUESTION

## OUTPUT:

Respond with ONLY one word: SIMPLE_QUESTION or NOT_SIMPLE_QUESTION
