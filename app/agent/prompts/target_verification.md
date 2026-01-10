User wants to target "{entity_name}".
User's original query: "{original_query}"
User's context/constraints: {user_context}

Based on these search results, identify the likely entities.

SEARCH RESULTS:
{research_str}

Analyze the following:
1. Is there a clearly dominant official domain for this entity?
2. Does the user's context (location, industry, TLD hint) filter the candidates?
   - If user mentions "South Africa", prioritize .co.za or SA-based entities.
   - If user mentions "fintech", ignore social apps.
   - If user mentions ".za", prioritize South African domains.
3. If still ambiguous after applying user context, what question would clarify?

Return STRICT JSON format only. No comments. No markdown.
{{
  "status": "clear" | "ambiguous" | "unknown",
  "primary_domain": "example.com" (if clear after applying user context),
  "candidates": [
     {{"name": "Entity Name", "domain": "domain.com", "desc": "Short description", "location": "Country/City"}},
     ...
  ],
  "clarification_question": "Question to ask user if still ambiguous"
}}
