# Test Cases

| TC ID | Scenario | Input | Expected Result | Evidence |
|---|---|---|---|---|
| TC01 | Normal traffic | `make simulate-normal` | No critical alert for normal browsing | `data/logs/events.jsonl` |
| TC02 | Port scan | `make simulate-portscan` | Port scan alert from R002 and/or ML | `data/logs/alerts.csv` |
| TC03 | Brute force | `make simulate-bruteforce` | Brute force alert from R001 and ML | Dashboard screenshot |
| TC04 | Web attack | `make simulate-webattack` | Web attack alert from R004 and ML | `data/logs/events.jsonl` |
| TC05 | Traffic spike | `make simulate-spike` | Traffic spike alert from R003 and ML | Dashboard chart |
| TC06 | False positive case | High-volume but labeled normal events | Low/medium/no alert documented | `demo_summary.md` |
| TC07 | False negative case | Weak suspicious pattern below thresholds | May be missed and documented as limitation | `demo_summary.md` |

## Automated Tests

Run:

```bash
make test
```

Covered behaviors:

- preprocessing missing values,
- feature column stability,
- JSONL read/write,
- rule-based brute force detection,
- severity mapping,
- detection CLI alert output,
- simulator safe markers,
- evidence export,
- Flask lab event logging,
- FastAPI single-event detection,
- dashboard missing-data handling.
