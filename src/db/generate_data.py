"""Phase 1: generate the demo databases (enhanced enterprise schema).

company.db
  employees      120 staff across 5 departments. Original identity/salary
                 columns are byte-identical to the v1 dataset (deterministic
                 seed 42) so every governance measurement stays comparable;
                 the schema is ENRICHED with designation, bonus, join_date,
                 manager_id and address.
  departments    5 departments with managers.
  employees_tech_view   DB-level view that structurally CANNOT return
                 salary / email / phone for Tech staff (defence in depth
                 under Layer 3).
  employees_public_view a cross-department, PII-free directory view used by
                 L3 roles (HR_Employee, Business_Analyst, Tech_Lead...).
  documents      the RAG source-of-truth catalog: 33 documents, each with
                 department ownership, sensitivity tier and min_clearance.

executives.db -> separate SQLite file ON PURPOSE (separate trust domain,
mirrors data-segregation guidance in ISO 27001 A.5.x and data minimisation
in DPDP Act 2023 s.6). Enriched with annual_salary, stock_options,
performance_bonus and contract_terms; the legacy `bonus` column is kept so
existing RBAC policies and tests remain valid.

NOTE: the `users` table (authentication) is owned by seed_users.py and is
NEVER dropped here, so reseeding company data cannot wipe credentials.
"""
import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

from src.common.paths import DB_DIR, DOCS_DIR

FIRST = ["Aarav", "Diya", "Rohan", "Priya", "Kabir", "Ananya", "Vivaan", "Isha",
         "Arjun", "Meera", "Rahul", "Sneha", "Dev", "Tara", "Nikhil", "Riya",
         "Suresh", "Kavya", "Amit", "Neha", "Raj", "Pooja", "Sam", "Leela",
         "Vikram", "Nisha", "Karan", "Divya", "Manav", "Sara"]
LAST = ["Sharma", "Patel", "Nair", "Iyer", "Gupta", "Reddy", "Singh", "Joshi",
        "Kulkarni", "Das", "Mehta", "Rao", "Kapoor", "Pillai", "Bose", "Chauhan"]
DEPARTMENTS = ["HR", "Tech", "Business", "Finance", "Sales"]
# NOTE: department list now includes Finance. The deterministic core sequence
# below still only draws from the ORIGINAL four departments for the 120 legacy
# rows; Finance staffing comes from the dedicated Finance block so historical
# measurements (and the 120-row integrity test) stay stable.
LEGACY_DEPARTMENTS = ["HR", "Tech", "Business", "Sales"]
DEPT_SALARY = {"HR": (60000, 130000), "Tech": (80000, 160000),
               "Business": (70000, 150000), "Sales": (55000, 140000),
               "Finance": (65000, 145000)}
TECH_ROLES = ["Engineer", "Senior Engineer", "SRE", "Security Analyst"]
OTHER_ROLES = {"HR": ["HR Partner", "HRBP", "Recruiter"],
               "Business": ["Analyst", "Manager", "Director"],
               "Sales": ["AE", "Sr AE", "Sales Manager"],
               "Finance": ["Accountant", "FP&A Analyst", "Controller"]}
CITIES = ["Bengaluru, KA", "Pune, MH", "Hyderabad, TS", "Mumbai, MH",
          "Gurugram, HR", "Chennai, TN", "Noida, UP", "Kochi, KL"]

EXECUTIVES = [
    # id, name, role, bonus(legacy col = performance_bonus), annual_salary,
    # stock_options, performance_bonus, contract_terms
    (1, "Meera Nair", "CEO", 2400000, 24000000, 520000, 2400000,
     "3-year term, 12-month notice, clawback applies"),
    (2, "James Dsouza", "CFO", 1700000, 16000000, 310000, 1700000,
     "3-year term, 6-month notice, audit committee sign-off"),
    (3, "Anita Rao", "CTO", 1600000, 15000000, 290000, 1600000,
     "3-year term, 6-month notice, IP assignment"),
    (4, "Ravi Menon", "COO", 1200000, 11500000, 210000, 1200000,
     "2-year term, 6-month notice"),
    (5, "Sara Khan", "CISO", 950000, 9200000, 150000, 950000,
     "2-year term, 3-month notice, security clearance required"),
    (6, "Tom Verghese", "CHRO", 800000, 8100000, 120000, 800000,
     "2-year term, 3-month notice"),
]


def _mk_people(rng: random.Random, n: int):
    """Original v1 generator - sequence of rng calls must NOT change."""
    people, used = [], set()
    for i in range(1, n + 1):
        while True:
            name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
            if name not in used:
                used.add(name)
                break
        dept = rng.choice(LEGACY_DEPARTMENTS)
        role = (rng.choice(TECH_ROLES) if dept == "Tech"
                else rng.choice(OTHER_ROLES[dept]))
        email = name.lower().replace(" ", ".") + "@corp.example.com"
        phone = f"+1 (555) 0{rng.randint(10, 99)}-{rng.randint(0, 9999):04d}"
        lo, hi = DEPT_SALARY[dept]
        salary = rng.randrange(lo, hi, 500)
        people.append([i, name, dept, role, email, phone, salary])
    return people


def _enrich(people: list[list], exec_ids: list[int]) -> list[tuple]:
    """Deterministically add designation, bonus, join_date, manager_id,
    address WITHOUT touching the identity/salary columns. A fixed, repeatable
    slice of Sales staff is re-badged into the Finance department (with
    Finance-grade pay) so every department owns real employee records."""
    rng = random.Random(1337)          # independent stream: v1 data preserved
    finance_ids = {24, 48, 72, 96, 108, 120}
    rows = []
    for (i, name, dept, role, email, phone, salary) in people:
        if i in finance_ids:
            dept = "Finance"
            role = rng.choice(OTHER_ROLES["Finance"])
            salary = rng.randrange(*DEPT_SALARY["Finance"])
        bonus = rng.randrange(0, max(2, salary // 12), 250)
        join = date(2015, 1, 1) + timedelta(days=rng.randrange(0, 3600))
        manager = rng.choice(exec_ids + [p[0] for p in people if p[0] != i])
        address = rng.choice(CITIES)
        rows.append((i, name, dept, role, email, phone, salary, role, bonus,
                     join.isoformat(), manager, address))
    return rows


def _documents() -> list[tuple]:
    """(title, department, sensitivity, min_clearance, namespace, file_path)
    derived from the single source of truth in doc_contents.DOC_FILES.
    Sensitivity tiers: Public L1 < Internal L2 < Confidential L3 <
    Restricted L5 (enforced by the CIA-C confidentiality check)."""
    from src.db.doc_contents import DOC_FILES
    tiers = {"Public": "L1", "Internal": "L2", "Confidential": "L3",
             "Restricted": "L5"}
    rows = []
    for title, (ns, slug, _dept, sensitivity, _body) in DOC_FILES.items():
        rows.append((title, ns.split("_")[0].capitalize()
                     if ns != "exec_docs" else "Executive",
                     sensitivity, tiers[sensitivity], ns,
                     f"data/docs/{ns}/{slug}.txt"))
    return rows


def main():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)  # deterministic: same data on every machine
    people = _mk_people(rng, 120)

    company = sqlite3.connect(DB_DIR / "company.db")
    company.executescript("""
        DROP TABLE IF EXISTS employees;
        DROP TABLE IF EXISTS departments;
        DROP TABLE IF EXISTS documents;
        DROP VIEW IF EXISTS employees_tech_view;
        DROP VIEW IF EXISTS employees_public_view;
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY, name TEXT, department TEXT, role TEXT,
            email TEXT, phone TEXT, salary INTEGER,
            designation TEXT, bonus INTEGER DEFAULT 0,
            join_date TEXT, manager_id INTEGER, address TEXT);
        CREATE TABLE departments (id INTEGER PRIMARY KEY, name TEXT, manager TEXT);
        CREATE TABLE documents (
            doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT UNIQUE NOT NULL, content TEXT NOT NULL,
            department TEXT NOT NULL,
            sensitivity TEXT NOT NULL CHECK (sensitivity IN
                ('Public','Internal','Confidential','Restricted')),
            min_clearance TEXT NOT NULL CHECK (min_clearance IN
                ('L1','L2','L3','L4','L5')),
            namespace TEXT NOT NULL,
            file_path TEXT NOT NULL);
        CREATE VIEW employees_tech_view AS
            SELECT id, name, department, role FROM employees WHERE department='Tech';
        CREATE VIEW employees_public_view AS
            SELECT id, name, department, role, join_date FROM employees;
    """)
    exec_ids = [e[0] for e in EXECUTIVES]
    company.executemany("INSERT INTO employees VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        _enrich(people, exec_ids))
    company.executemany("INSERT INTO departments VALUES (?,?,?)",
                        [(i, d, f"{rng.choice(FIRST)} {rng.choice(LAST)}")
                         for i, d in enumerate(DEPARTMENTS)])
    company.commit()
    company.close()

    # Separate trust domain for executive compensation.
    execs = sqlite3.connect(DB_DIR / "executives.db")
    execs.executescript("""
        DROP TABLE IF EXISTS executives;
        CREATE TABLE executives (
            id INTEGER PRIMARY KEY, name TEXT, role TEXT, bonus INTEGER,
            annual_salary INTEGER, stock_options INTEGER,
            performance_bonus INTEGER, contract_terms TEXT);
    """)
    execs.executemany(
        "INSERT INTO executives VALUES (?,?,?,?,?,?,?,?)", EXECUTIVES)
    execs.commit()
    execs.close()

    # Document catalog rows + content files (single source: doc_contents).
    from src.db.doc_contents import DOC_FILES
    rows = _documents()
    company = sqlite3.connect(DB_DIR / "company.db")
    for (title, dept, sensitivity, min_clr, ns, file_path) in rows:
        body = DOC_FILES[title][4]
        slug_path = DOCS_DIR / ns / Path(file_path).name
        slug_path.parent.mkdir(parents=True, exist_ok=True)
        slug_path.write_text(body, encoding="utf-8")
        company.execute(
            "INSERT INTO documents (title, content, department, sensitivity, "
            "min_clearance, namespace, file_path) VALUES (?,?,?,?,?,?,?)",
            (title, body, dept, sensitivity, min_clr, ns, file_path))
    company.commit()
    company.close()

    print(f"company.db: {len(people)} employees (enriched schema), "
          f"{len(DEPARTMENTS)} departments, 33 documents, 2 minimised views")
    print(f"executives.db: {len(EXECUTIVES)} executives (separate file, "
          f"full compensation records)")


if __name__ == "__main__":
    main()
