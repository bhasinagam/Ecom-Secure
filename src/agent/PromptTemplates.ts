/**
 * Prompt Templates for LLM Analysis
 */

export const PROMPT_TEMPLATES = {
    VULNERABILITY_ANALYSIS: `You are a security researcher analyzing potential e-commerce vulnerabilities.

## Original Request
{{originalRequest}}

## Modified Request (Exploit Attempt)
{{modifiedRequest}}

## Server Response
Status: {{responseStatus}}
Body: {{responseBody}}

## Detector
Name: {{detectorName}}
Preliminary Finding: {{preliminaryVerdict}}

## Analysis Task
Determine if this is a GENUINE security vulnerability or a FALSE POSITIVE.

Consider:
1. Did the server accept the malicious payload without proper validation?
2. Does the response indicate successful exploitation (e.g., order created with manipulated price)?
3. Could this be legitimate application behavior (e.g., authorized discounts)?
4. Is there evidence of server-side validation that was bypassed?
5. What is the exploitability in a real-world scenario?

Respond in JSON:
{
  "is_vulnerable": boolean,
  "confidence": 0.0-1.0,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "reasoning": "string (2-3 sentences)",
  "exploitation_steps": ["step1", "step2", ...],
  "business_impact": "string",
  "cvss_score": 0.0-10.0
}`,

    PAYLOAD_GENERATION: `You are a penetration testing expert specializing in e-commerce vulnerabilities.

Context:
- Parameter name: {{parameterName}}
- Original value: {{originalValue}}
- Data type: {{parameterType}}
- Platform: {{platform}}
- Observed validation: {{observedValidation}}

Task: Generate 10 creative payloads that could exploit this parameter in a checkout flow.
Consider: type confusion, business logic flaws, edge cases, encoding tricks.

Respond with JSON array:
[
  {
    "payload": <value>,
    "attack_type": "string",
    "rationale": "string",
    "likelihood": 0.0-1.0
  }
]`,

    FALSE_POSITIVE_ANALYSIS: `You are a security analyst reviewing a potential vulnerability finding.

## Finding Details
Type: {{vulnType}}
Detector: {{detectorName}}
Parameter: {{parameter}}
Endpoint: {{endpoint}}

## Evidence
{{evidence}}

## Question
Is this likely a FALSE POSITIVE? Consider:
1. Common e-commerce patterns that might explain this behavior
2. Legitimate business logic that could cause this response
3. Signs of actual server-side validation
4. Context from the platform type

Respond in JSON:
{
  "is_false_positive": boolean,
  "confidence": 0.0-1.0,
  "reasoning": "string",
  "verification_steps": ["step1", "step2"]
}`,

    IMPACT_ASSESSMENT: `You are a security consultant assessing business impact of a vulnerability.

## Vulnerability
Type: {{vulnType}}
Severity: {{severity}}
Description: {{description}}

## Context
Platform: {{platform}}
Endpoint Type: {{endpointType}}

## Task
Assess the business impact of this vulnerability.

Respond in JSON:
{
  "financial_risk": "LOW|MEDIUM|HIGH|CRITICAL",
  "estimated_loss": "string (e.g., '$10,000 - $100,000 per incident')",
  "reputation_impact": "string",
  "regulatory_impact": "string",
  "remediation_priority": "IMMEDIATE|HIGH|MEDIUM|LOW",
  "remediation_steps": ["step1", "step2"]
}`,
};

/**
 * Fill template with values
 */
export function fillTemplate(template: string, values: Record<string, string>): string {
    let result = template;
    for (const [key, value] of Object.entries(values)) {
        result = result.replace(new RegExp(`{{${key}}}`, 'g'), value);
    }
    return result;
}
