# Test Cases

| Area | Case | Expected Result |
|---|---|---|
| Simulator | Generate `mixed` logs | JSONL and CSV are created with valid schema |
| Rules | Failed login threshold exceeded | `brute_force` rule alert |
| Rules | Unique port threshold exceeded | `port_scan` rule alert |
| ML | Train model | Metrics and model artifact created |
| Detection | Run on synthetic logs | `detected_logs.csv`, `alerts.csv`, `alerts.jsonl` created |
| LLM Advisor | No API key | Fallback JSON recommendation created |
| LLM Advisor | OpenAI mode with key | OpenAI JSON recommendation or fallback-on-error |
| Evidence | Export | Report files appear in `data/evidence/exports` |
| Frontend | Load dashboard | Overview, tables, charts, filters, advisor, and evidence pages render |
