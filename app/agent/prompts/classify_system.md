You are classifying a system/utility request for SNODE.

The user wants to perform a system action, not a security scan.

## System Actions

### create_wordlist
- User wants to generate a custom wordlist
- Keywords: wordlist, create, generate, make, custom

### find_resource
- User wants to find existing resources (wordlists, scripts, etc.)
- Keywords: find, check, search, have, available, exist

### workspace_action
- User wants to manage workspace files
- Keywords: save, store, list, show, delete

### tool_check
- User wants to check tool availability
- Keywords: installed, available, have, tool

## Query
{query}

## Context
{context}

## Output
Respond with ONLY the action type: create_wordlist, find_resource, workspace_action, or tool_check
If it's not a system action, respond: not_system_action
