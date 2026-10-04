# Attack campaign - secured mode, slice=llm

- corpus rows: 1130 | results: 1130
- containment: **100.0%** | leak rate: **0.0%**
- backend: mock (naive raw-model stand-in) | ruleset 3.0 | duration 5.1s

| OWASP | attacks | blocked | denied | leaked | block % | leak % | p95 ms |
|---|---|---|---|---|---|---|---|
| LLM01 | 150 | 132 | 18 | 0 | 100.0 | 0.0 | 6.1 | 
| LLM02 | 120 | 99 | 21 | 0 | 100.0 | 0.0 | 5.7 | 
| LLM03 | 100 | 61 | 39 | 0 | 100.0 | 0.0 | 5.9 | 
| LLM04 | 100 | 67 | 33 | 0 | 100.0 | 0.0 | 6.2 | 
| LLM05 | 120 | 93 | 27 | 0 | 100.0 | 0.0 | 4.9 | 
| LLM06 | 120 | 95 | 25 | 0 | 100.0 | 0.0 | 5.3 | 
| LLM07 | 120 | 97 | 23 | 0 | 100.0 | 0.0 | 5.1 | 
| LLM08 | 100 | 65 | 35 | 0 | 100.0 | 0.0 | 5.2 | 
| LLM09 | 100 | 34 | 66 | 0 | 100.0 | 0.0 | 5.4 | 
| LLM10 | 100 | 42 | 58 | 0 | 100.0 | 0.0 | 6.3 | 
