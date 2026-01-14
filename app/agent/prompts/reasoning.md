# Reasoning Prompt - Comprehensive Analysis

Analyze comprehensive security testing results and provide final assessment, recommendations, and next steps.

## COMPLETE RESULTS SUMMARY:
{results_summary}

## CHECKLIST PROGRESS:
{checklist_progress}

## CONTEXT:
{context_summary}

## ANALYSIS REQUIREMENTS:

Provide a comprehensive analysis covering:

### 1. Executive Summary
- Overall assessment of the security testing
- Key findings at a glance
- Risk level (Critical/High/Medium/Low)

### 2. Vulnerabilities Found
- List all discovered vulnerabilities
- Severity classification
- Affected systems/services
- Potential impact

### 3. Attack Vectors Identified
- Successful attack paths
- Exploitation opportunities
- Privilege escalation possibilities
- Lateral movement opportunities

### 4. Risk Assessment
- Critical risks requiring immediate attention
- High-priority security gaps
- Compliance concerns
- Business impact analysis

### 5. Recommendations
- Immediate actions (Critical/High severity)
- Short-term remediation (Medium severity)
- Long-term security improvements
- Best practices to implement

### 6. Next Steps
- Additional testing needed
- Areas requiring deeper investigation
- Follow-up actions
- Monitoring recommendations

## OUTPUT FORMAT:

Provide a structured analysis in markdown format:

```markdown
# Security Assessment Report

## Executive Summary
[Overall assessment, risk level, key findings]

## Vulnerabilities Discovered
[Detailed list with severity and impact]

## Attack Vectors
[Successful attack paths and exploitation opportunities]

## Risk Assessment
[Critical risks and business impact]

## Recommendations
[Prioritized remediation steps]

## Next Steps
[Additional testing and follow-up actions]
```

## GUIDELINES:

1. **Be Specific**: Reference specific findings, tools used, and results
2. **Prioritize**: Focus on Critical/High severity issues first
3. **Actionable**: Provide concrete, actionable recommendations
4. **Comprehensive**: Cover all phases of testing performed
5. **Risk-Focused**: Emphasize business impact and security risks
6. **Professional**: Use clear, professional language suitable for stakeholders

## EXAMPLES:

### Example 1: Successful Attack
**Input**: Results from full PTES flow with vulnerabilities found

**Output**:
```markdown
# Security Assessment Report

## Executive Summary
Security assessment of example.com revealed **3 Critical** and **5 High** severity vulnerabilities. The target is vulnerable to SQL injection, XSS, and weak authentication mechanisms. **Risk Level: CRITICAL**

## Vulnerabilities Discovered
1. **SQL Injection (Critical)** - Found in /login endpoint
   - Impact: Full database compromise possible
   - Affected: Authentication system
   
2. **Cross-Site Scripting (High)** - Found in search functionality
   - Impact: Session hijacking, credential theft
   - Affected: User-facing application

## Attack Vectors
- SQL injection → Database access → Credential extraction → Lateral movement
- XSS → Session hijacking → Account takeover

## Recommendations
1. **Immediate**: Patch SQL injection vulnerability (Critical)
2. **Short-term**: Implement input validation and output encoding
3. **Long-term**: Security code review and penetration testing program
```

Return comprehensive analysis in markdown format.
