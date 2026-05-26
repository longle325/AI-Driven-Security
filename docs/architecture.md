# Architecture

```text
Synthetic logs / Safe lab web
          |
          v
Data loader + feature engineering
          |
          +--> Rule detector
          |
          +--> Random Forest classifier
          |
          v
Alert manager
          |
          v
LLM Incident Advisor
          |
          v
React TypeScript dashboard + evidence exports
```

Services:

- `frontend`: React TypeScript SOC dashboard on port `8501`.
- `detection-api`: FastAPI backend on port `8000`.
- `lab-web`: safe local Flask app on port `5001`.
- `trainer`, `simulator`, `detector`, `advisor`, `exporter`: one-shot Docker services for the demo pipeline.
