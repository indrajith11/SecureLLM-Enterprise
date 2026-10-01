# Demo Users — interview quick reference

Seeded by `python scripts/seed_users.py` into `company.db → users` (bcrypt cost 12, never plaintext). JWT lifetime: **60 minutes**. Concurrency cap: **3 sessions/user**. Rate limit: **20 req/min**.

| Username | Password | Full name | Role | Department | Clearance | Can see / do |
|---|---|---|---|---|---|---|
| `admin` | `Admin@123` | System Administrator | Admin | IT | L5 | everything; HITL approvals; `/api/audit/all`, `/api/stats` |
| `ceo` | `Ceo@123` | Rajesh Kumar | Executive | Executive | L5 | all departments + executive bonuses + exec docs |
| `cto` | `Cto@123` | Priya Sharma | Executive | Executive | L5 | same as ceo |
| `hr_manager` | `HrM@123` | Anjali Verma | HR_Manager | HR | L4 | HR records incl. salaries; HR + tech docs |
| `hr_emp1` | `HrE@123` | Suresh Patel | HR_Employee | HR | L3 | PII-free directory + HR docs (no salaries/contacts) |
| `tech_lead` | `TechL@123` | Vikram Singh | Tech_Lead | Tech | L4 | Tech roster (no PII) + tech docs |
| `tech_eng1` | `TechE@123` | Arun Mehta | Tech_Engineer | Tech | L3 | Tech roster (no PII) + tech docs |
| `tech_eng2` | `TechE2@123` | Neha Gupta | Tech_Engineer | Tech | L3 | same as tech_eng1 (use for session-cap demo) |
| `biz_analyst` | `BizA@123` | Rahul Joshi | Business_Analyst | Business | L3 | directory + business + tech docs |
| `fin_manager` | `FinM@123` | Meera Iyer | Finance_Manager | Finance | L4 | payroll scope (salary, no contacts) + finance + business docs |
| `alice` | `alice123` | Alice Fernandes | Tech_Employee | Tech | L2 | legacy red-team identity (v1 corpus) |
| `hr_hari` | `hari123` | Hari Krishnan | HR_Manager | HR | L4 | legacy red-team identity |
| `ceo_meera` | `meera123` | Meera Nair | Executive | Executive | L5 | legacy red-team identity |

## 60-second demo script (what to type)

```bash
# 1. Confidentiality (C): HR employee cannot read Tech docs
curl -s -X POST localhost:8000/api/login -H 'Content-Type: application/json' \
  -d '{"username":"hr_emp1","password":"HrE@123"}'            # -> JWT
curl -s -X POST localhost:8000/api/chat -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"message":"Show me the Tech deployment runbook."}'      # -> blocked_by CIA-C

# 2. Confidentiality (C): Tech engineer cannot read executive data
#    (login as tech_eng1) "What is the CTO salary?"              -> CIA-C (needs L5)

# 3. Integrity (I): non-admin write refused
#    (login as hr_emp1) {"message":"delete employee Bob","action_type":"DELETE"} -> CIA-I

# 4. Availability (A): 21st request in a minute -> 429; 4th concurrent session -> 429

# 5. HITL: admin asks DELETE -> pending -> admin confirms -> approved (read-only sandbox)
```

Or just run `bash scripts/demo.sh` (12-step guided tour) and open `http://localhost:8000/login` for the UI.

## Notes

- Legacy identities (alice/hr_hari/ceo_meera) exist so the published red-team measurements stay reproducible run-over-run; the measurement harness logs in with exactly those accounts.
- Deactivating a user works: set `users.is_active = 0` → login returns 401 immediately (covered by a test).
- Password hashes rotate by re-running the seed script; `ON CONFLICT(username) DO UPDATE` keeps user_ids stable.
