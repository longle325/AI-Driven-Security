# LLM Advisor Design

The LLM Advisor receives structured alert context and returns structured defensive incident guidance.

Detection boundary:

- Rule detector and ML model classify events.
- Alert manager assigns severity and evidence references.
- LLM Advisor explains the generated alert and recommends defensive next steps.
- LLM output is advisory only and must be reviewed by a human.

Safety guardrails:

- No offensive exploitation steps.
- No public-IP scanning instructions.
- No malware or evasion guidance.
- Local lab assumptions only.

Default mode is `fallback`, so the demo works without an API key.
