USER MESSAGE: "{query}"

CONTEXT:
{context_summary}
{domain_note}

CLASSIFY AS ONE OF:

- SECURITY_TASK: User wants to RUN NEW ACTIONS using security/OSINT tools
  * Running scans: "scan domain", "use nuclei", "run nmap", "enumerate subdomains"
  * OSINT lookups: "lookup IP", "find real IP", "whois lookup", "get IP info", "resolve domain"
  * Active reconnaissance: "check SSL", "discover origin IP", "find origin server"
  * Any request involving a domain/IP that requires FETCHING NEW DATA from external sources
  * IMPORTANT: Handle typos! These are SECURITY_TASK:
    - "scna" = "scan", "scann" = "scan"
    - "chekc" = "check", "asess" = "assess", "assesss" = "assess"
    - "enumarte" = "enumerate", "eksploit" = "exploit"
    - Misspelled domain names like "exmaple.com" are still targets to scan
  
- MEMORY_QUERY: User wants to SEE/RETRIEVE ALREADY STORED DATA from previous scans
  * Only when user explicitly asks to SHOW/LIST/DISPLAY data already in memory
  * Examples: "show stored subdomains", "list our findings", "what did the previous scan find"
  * Key indicators: "show me", "list", "display", "what did we find" (referring to PAST results)
  
- QUESTION: Conceptual question needing explanation (no action, no data)
  * Examples: "what is XSS", "explain this CVE", "how does SQL injection work"
  * Identity questions: "who are you", "what are you", "what is SNODE", "what can you do"
  * General questions: "how does this work", "what is this", "tell me about X"
  * Questions WITHOUT domain/IP addresses and WITHOUT action verbs (scan, run, check, find, etc.)

IMPORTANT DISTINCTION:
- "lookup IP for domain.com" → SECURITY_TASK (needs to FETCH new data from external API)
- "show stored IPs" → MEMORY_QUERY (wants to see what's already saved)
- "find real IP address" → SECURITY_TASK (needs to perform OSINT lookup)

TYPO HANDLING:
If the message contains obvious typos but the intent is clear (e.g., "scna this wesbite"), 
still classify correctly. Don't reject unclear messages - try to understand the intent.

Respond with ONLY one word: SECURITY_TASK or MEMORY_QUERY or QUESTION
