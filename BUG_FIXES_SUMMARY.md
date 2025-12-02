# Bug Fixes Summary - Masscan/Naabu/Nmap DNS Resolution

## Issue Description

**Bug #3: Masscan DNS Resolution Failure**

When the LLM Phase 1 tool selector formatted tool arguments for multiple targets, it sometimes passed the targets as a **string representation of a Python list** instead of proper format:

```python
# What LLM passed (WRONG):
"targets": "['api.snode.com', 'admin.snode.com', 'dev.snode.com']"

# What should be passed (CORRECT):
"targets": "api.snode.com,admin.snode.com,dev.snode.com"  # or
"targets": ["api.snode.com", "admin.snode.com", "dev.snode.com"]
```

This caused DNS resolution to fail because the tools tried to resolve the literal string `['api.snode.com'` as a hostname.

**Error Output:**
```
[DNS] Warning: Could not resolve ['api.snode.com', using as-is
[DNS] Warning: Could not resolve 'admin.snode.com', using as-is
[DNS] Warning: Could not resolve 'dev.snode.com'], using as-is
⚠️  Masscan returned exit code 1
```

## Root Cause

The tools expected either:
- A single target string: `"example.com"`
- A comma-separated string: `"api.example.com,web.example.com"`
- A Python list: `["api.example.com", "web.example.com"]`

But the LLM occasionally passed a **stringified list**: `"['api.example.com', 'web.example.com']"`

The existing parsing logic didn't handle this case, treating it as a single malformed target.

## Solution

Added robust input sanitization using Python's `ast.literal_eval()` to detect and parse string representations of lists in all affected tools:

### 1. **masscan_tools.py**

**Lines 65-83** - Added parsing in `masscan_scan()`:
```python
if isinstance(targets, str):
    # Handle malformed input: LLM sometimes passes string representation of list
    if targets.startswith('[') and targets.endswith(']'):
        # Try to parse as Python list literal
        import ast
        try:
            parsed = ast.literal_eval(targets)
            if isinstance(parsed, list):
                targets = parsed
                print(f"    [PARSE] Converted string representation of list to actual list")
            else:
                targets = [targets]
        except (ValueError, SyntaxError):
            targets = [targets]
    else:
        targets = [targets]
```

**Lines 464-483** - Added parsing in `execute_masscan_tool()`:
```python
if 'targets' in tool_args and isinstance(tool_args['targets'], str):
    targets_str = tool_args['targets']

    if targets_str.startswith('[') and targets_str.endswith(']'):
        import ast
        try:
            parsed = ast.literal_eval(targets_str)
            if isinstance(parsed, list):
                tool_args['targets'] = parsed
            else:
                tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
        except (ValueError, SyntaxError):
            tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
    else:
        tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
```

### 2. **naabu_tools.py**

**Lines 40-58** - Added parsing in `naabu_scan()`:
```python
if isinstance(targets, str):
    if targets.startswith('[') and targets.endswith(']'):
        import ast
        try:
            parsed = ast.literal_eval(targets)
            if isinstance(parsed, list):
                targets = parsed
                print(f"    [PARSE] Converted string representation of list to actual list")
            else:
                targets = [targets]
        except (ValueError, SyntaxError):
            targets = [targets]
    else:
        targets = [targets]
```

**Lines 452-472** - Added parsing in `execute_naabu_tool()`:
```python
if 'targets' in tool_args and isinstance(tool_args['targets'], str):
    targets_str = tool_args['targets']

    if targets_str.startswith('[') and targets_str.endswith(']'):
        import ast
        try:
            parsed = ast.literal_eval(targets_str)
            if isinstance(parsed, list):
                tool_args['targets'] = parsed
            else:
                tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
        except (ValueError, SyntaxError):
            tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
    else:
        tool_args['targets'] = [t.strip() for t in targets_str.split(',')]
```

### 3. **nmap_tools.py**

**Lines 1164-1176** - Added parsing in `nmap_stealth_batch_scan()`:
```python
if isinstance(targets, str) and targets.startswith('[') and targets.endswith(']'):
    import ast
    try:
        parsed = ast.literal_eval(targets)
        if isinstance(parsed, list):
            target_list = [str(t).strip() for t in parsed if str(t).strip()]
        else:
            target_list = [t.strip() for t in targets.split(",") if t.strip()]
    except (ValueError, SyntaxError):
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
else:
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
```

### 4. **Bonus Fix: Unicode Arrow Character**

**masscan_tools.py:37** - Fixed Windows encoding issue:
```python
# Before:
print(f"    [DNS] Resolved {hostname} → {ip}")

# After:
print(f"    [DNS] Resolved {hostname} -> {ip}")
```

## Verification

Created test script `test_masscan_fix.py` that verifies all three input formats:

**Test Results:**
```
TEST 1: String representation of list (the bug)
    [DNS] Resolved api.snode.com -> 125.235.4.59
    [DNS] Resolved admin.snode.com -> 125.235.4.59
    [DNS] Resolved dev.snode.com -> 125.235.4.59
    [DEDUP] Removed 2 duplicate IPs (1 unique IPs to scan)
✅ SUCCESS - All 3 domains properly parsed and resolved!

TEST 2: Normal comma-separated string
    [DNS] Resolved api.snode.com -> 125.235.4.59
    [DNS] Resolved admin.snode.com -> 125.235.4.59
    [DNS] Resolved dev.snode.com -> 125.235.4.59
    [DEDUP] Removed 2 duplicate IPs (1 unique IPs to scan)
✅ SUCCESS - Comma-separated format still works!

TEST 3: Single target
    [DNS] Resolved api.snode.com -> 125.235.4.59
✅ SUCCESS - Single target format still works!
```

## Impact

This fix ensures that **all three port scanning tools** (Masscan, Naabu, Nmap) can handle:

1. **Malformed LLM output** - String representation of lists (the bug)
2. **Standard formats** - Comma-separated strings
3. **Single targets** - Single domain/IP strings
4. **Native lists** - Python list objects

The fix is **defensive** and **backwards compatible** - it doesn't break any existing functionality while adding robustness against LLM formatting inconsistencies.

## Files Modified

1. `tools/masscan_tools.py` - Lines 37, 65-83, 464-483
2. `tools/naabu_tools.py` - Lines 40-58, 452-472
3. `tools/nmap_tools.py` - Lines 1164-1176

## Related Bugs

- **Bug #1**: Nmap not executing - Fixed in agent.py:1171 (added return statement)
- **Bug #2**: Shodan domain resolution - Fixed in shodan_tools.py:25-45 (added DNS resolution)
- **Bug #3**: Masscan DNS parsing - Fixed in this update

All three major bugs from the "Full assessment of snode.com" test are now resolved!
