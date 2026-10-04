# Attack campaign - baseline mode, slice=adv

- corpus rows: 500 | results: 500
- containment: **15.0%** | leak rate: **85.0%**
- backend: mock (naive raw-model stand-in) | ruleset 3.0 | duration 2.6s

| OWASP | attacks | blocked | denied | leaked | block % | leak % | p95 ms |
|---|---|---|---|---|---|---|---|
| ADVANCED | 500 | 0 | 75 | 425 | 15.0 | 85.0 | 5.1 | 
