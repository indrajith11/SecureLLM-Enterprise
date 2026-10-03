"""Dataset v2: realistic example-enterprise extension of the demo database.

Builds the blueprint layers ON TOP of the deterministic legacy seed without
touching a single legacy row (all v2 rows live in a dedicated id space
guarded by the dataset_meta marker, so reseeding is fully idempotent):

  SQL (company.db)
    companies / locations / teams / org_hierarchy / employee_pii /
    document_acl / data_classification / retention_rules /
    document_versions / dataset_meta + 67 additive employees across the
    NEW departments (IT, Legal, Marketing, Operations) + backfill for
    HR/Tech/Finance + 50 new `documents` rows from doc_contents_v2.

  TRUST DOMAIN (the point of employee_pii)
    PAN / Aadhaar / bank details are REALISTIC IN SHAPE and FAKE IN FACT,
    and the table is deliberately ABSENT from rbac_config.table_catalog:
    the governed SQL layer is structurally blind to it (defence in depth
    under Layer 3 and data minimisation per DPDP Act 2023 s.6 - the same
    pattern as executives.db). data_classification records the field-level
    sensitivity so auditors see exactly what is protected where.

  ARTIFACTS (written next to the SQL so the demo corpus spans formats)
    data/pdfs/<dept>/  - styled PDF twin of every RAG document (83),
                         Hindi documents shaped via PIL+raqm (complex
                         script rendering reportlab lacks)
    data/excel/        - 12 workbooks generated FROM the live database so
                         cross-department values always agree
    data/images/       - logo, org chart, floor plan, GST-style invoice
                         scans (Pillow, deterministic)
    data/metadata/     - document_metadata / document_acl /
                         data_classification / retention_rules YAML
"""
from __future__ import annotations

import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import yaml

from src.common.paths import COMPANY_DB, DATA_DIR, DB_DIR, DOCS_DIR
from src.db.doc_contents import DOC_FILES
from src.db.doc_contents_v2 import DOC_VERSIONS, NEW_DOCS, TRAP_SLUGS

V2_MARKER = "v2_employee_start"
NEW_DEPARTMENTS = ["IT", "Legal", "Marketing", "Operations"]
PDF_FOLDER = {"hr_docs": "hr", "tech_docs": "engineering",
              "business_docs": "sales_marketing", "finance_docs": "finance",
              "exec_docs": "executive", "it_docs": "it",
              "legal_docs": "legal", "ops_docs": "operations",
              "trap_docs": "trap_decoys"}
PDF_DIR = DATA_DIR / "pdfs"
EXCEL_DIR = DATA_DIR / "excel"
IMG_DIR = DATA_DIR / "images"
META_DIR = DATA_DIR / "metadata"

FIRST = ["Aarav", "Diya", "Rohan", "Priya", "Kabir", "Ananya", "Vivaan",
         "Isha", "Arjun", "Meera", "Rahul", "Sneha", "Dev", "Tara",
         "Nikhil", "Riya", "Suresh", "Kavya", "Amit", "Neha", "Raj",
         "Pooja", "Sam", "Leela", "Vikram", "Nisha", "Karan", "Divya",
         "Manav", "Sara", "Aditi", "Farhan", "Gauri", "Harish", "Indira",
         "Jai", "Lakshmi", "Mohan", "Nandini", "Omkar"]
LAST = ["Sharma", "Patel", "Nair", "Iyer", "Gupta", "Reddy", "Singh",
        "Joshi", "Kulkarni", "Das", "Mehta", "Rao", "Kapoor", "Pillai",
        "Bose", "Chauhan", "Deshmukh", "Menon", "Bhatt", "Verma"]
CITIES = ["Bengaluru, KA", "Pune, MH", "Hyderabad, TS", "Mumbai, MH",
          "Gurugram, HR", "Chennai, TN", "Noida, UP", "Kochi, KL"]
V2_ROLES = {
    "IT": ["IT Support Engineer", "System Administrator", "Network Engineer",
           "IT Ops Analyst"],
    "Legal": ["Legal Counsel", "Contract Manager", "Paralegal",
              "Compliance Officer"],
    "Marketing": ["Marketing Analyst", "Content Strategist",
                  "Campaign Manager", "Brand Designer"],
    "Operations": ["Facilities Coordinator", "Ops Executive",
                   "Admin Specialist", "EHS Officer"],
    "HR": ["HR Partner", "Recruiter", "HRBP"],
    "Tech": ["Engineer", "Senior Engineer", "SRE", "Security Analyst"],
    "Finance": ["Accountant", "FP&A Analyst"],
}
V2_SALARY = {"IT": (60000, 140000), "Legal": (90000, 165000),
             "Marketing": (65000, 135000), "Operations": (55000, 120000),
             "HR": (60000, 130000), "Tech": (80000, 160000),
             "Finance": (65000, 145000)}
V2_PLAN = [("IT", 15), ("Legal", 6), ("Marketing", 10), ("Operations", 12),
           ("HR", 8), ("Tech", 8), ("Finance", 8)]   # 67 additive staff


# ==================================================================== SQL
def _v2_start(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS dataset_meta ("
                 "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = conn.execute("SELECT value FROM dataset_meta WHERE key=?",
                       (V2_MARKER,)).fetchone()
    return int(row[0]) if row else 200


def extend_database() -> dict:
    """Idempotent v2 extension of company.db. Returns a counts report."""
    conn = sqlite3.connect(COMPANY_DB)
    conn.row_factory = sqlite3.Row
    start = _v2_start(conn)
    report: dict = {}

    _create_tables(conn)
    _upsert_company_profile(conn)
    _upsert_locations_teams(conn)
    n_emp = _insert_employees(conn, start)
    _build_org_hierarchy(conn)
    _write_new_doc_txt_files()
    n_docs = _insert_new_documents(conn)
    _fill_employee_pii(conn)
    _build_document_acl(conn)
    _build_document_versions(conn)
    _build_data_classification(conn)
    _build_retention_rules(conn)
    conn.commit()
    conn.close()

    report.update({"new_employees": n_emp, "new_documents": n_docs,
                   "v2_start_id": start})
    return report


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, legal_name TEXT,
        industry TEXT, cin TEXT, gstin TEXT, company_pan TEXT,
        hq_city TEXT, country TEXT, address TEXT, founded_year INTEGER);
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY, name TEXT, city TEXT, country TEXT,
        office_type TEXT CHECK (office_type IN
            ('HQ','Branch','Remote')), address TEXT);
    CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, department TEXT NOT NULL,
        lead_name TEXT, location_city TEXT);
    CREATE TABLE IF NOT EXISTS org_hierarchy (
        emp_id INTEGER PRIMARY KEY, emp_name TEXT NOT NULL,
        department TEXT NOT NULL, reports_to_id INTEGER,
        reports_to_name TEXT);
    CREATE TABLE IF NOT EXISTS employee_pii (
        emp_id INTEGER PRIMARY KEY REFERENCES employees(id),
        emp_code TEXT UNIQUE NOT NULL, pan TEXT, aadhaar TEXT,
        bank_ifsc TEXT, bank_account TEXT, personal_email TEXT,
        date_of_birth TEXT,
        CONSTRAINT pii_fake_demo CHECK (length(pan) = 10 AND
                                        length(aadhaar) = 12));
    CREATE TABLE IF NOT EXISTS document_acl (
        doc_id INTEGER NOT NULL REFERENCES documents(doc_id),
        role TEXT NOT NULL, can_read INTEGER NOT NULL,
        can_download INTEGER NOT NULL,
        PRIMARY KEY (doc_id, role));
    CREATE TABLE IF NOT EXISTS data_classification (
        schema_table TEXT NOT NULL, column_name TEXT NOT NULL,
        classification TEXT NOT NULL CHECK (classification IN
            ('Public','Internal','Confidential','Restricted')),
        pii INTEGER NOT NULL DEFAULT 0, note TEXT,
        PRIMARY KEY (schema_table, column_name));
    CREATE TABLE IF NOT EXISTS retention_rules (
        doc_type TEXT PRIMARY KEY, retention_years REAL NOT NULL,
        purge_policy TEXT NOT NULL, legal_basis TEXT);
    CREATE TABLE IF NOT EXISTS document_versions (
        title TEXT PRIMARY KEY, slug TEXT NOT NULL, version TEXT NOT NULL,
        effective_date TEXT NOT NULL, status TEXT NOT NULL
            CHECK (status IN ('current','superseded')),
        supersedes TEXT, superseded_by TEXT);
    """)


def _upsert_company_profile(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM companies")
    conn.execute("INSERT INTO companies VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
        1, "TechNova Solutions", "TechNova Solutions Private Limited",
        "IT services and enterprise platforms", "U72900KA2015PTC089123",
        "29ABCDE1234F1Z5", "ABCDE1234F", "Bengaluru", "India",
        "Tower B, Prestige Tech Park, Outer Ring Road, Kadubeesanahalli, "
        "Bengaluru 560103", 2015))


def _upsert_locations_teams(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM locations")
    rows = [
        (1, "Bengaluru HQ", "Bengaluru", "India", "HQ",
         "Tower B, Prestige Tech Park, ORR, Bengaluru 560103"),
        (2, "Mumbai Office", "Mumbai", "India", "Branch",
         "Nariman Point Business Centre, Mumbai 400021"),
        (3, "Gurugram Office", "Gurugram", "India", "Branch",
         "Cyber City Block 4, Gurugram 122002"),
        (4, "Hyderabad Office", "Hyderabad", "India", "Branch",
         "HITEC City Madhapur, Hyderabad 500081"),
        (5, "Pune Office", "Pune", "India", "Branch",
         "Rajiv Gandhi Infotech Park, Hinjewadi Phase 2, Pune 411057"),
        (6, "Chennai Office", "Chennai", "India", "Branch",
         "Tidel Park, Taramani, Chennai 600113"),
        (7, "Remote India", "Multiple", "India", "Remote",
         "Distributed workforce - registered home offices"),
    ]
    conn.executemany("INSERT INTO locations VALUES (?,?,?,?,?,?)", rows)
    conn.execute("DELETE FROM teams")
    teams = [
        (1, "Platform Engineering", "Tech", "Vikram Singh", "Bengaluru"),
        (2, "Security Engineering", "Tech", "Arun Mehta", "Bengaluru"),
        (3, "People Operations", "HR", "Anjali Verma", "Bengaluru"),
        (4, "Talent Acquisition", "HR", "Suresh Patel", "Mumbai"),
        (5, "FP&A", "Finance", "Meera Iyer", "Bengaluru"),
        (6, "Enterprise Sales", "Business", "Rahul Joshi", "Gurugram"),
        (7, "IT Service Desk", "IT", "Kavya Menon", "Hyderabad"),
        (8, "Infrastructure and Network", "IT", "Farhan Bhatt", "Pune"),
        (9, "Contracts and Counsel", "Legal", "Gauri Deshpande", "Bengaluru"),
        (10, "Brand and Digital", "Marketing", "Nandini Rao", "Mumbai"),
        (11, "Workplace and EHS", "Operations", "Mohan Iyer", "Bengaluru"),
    ]
    conn.executemany("INSERT INTO teams VALUES (?,?,?,?,?)", teams)


def _insert_employees(conn: sqlite3.Connection, start: int) -> int:
    """67 additive employees in the v2 id space (>= start). Idempotent:
    previous v2 rows are deleted first, so ids are stable across runs."""
    conn.execute("DELETE FROM employees WHERE id >= ?", (start,))
    conn.execute("DELETE FROM employee_pii WHERE emp_id >= ?", (start,))
    rng = random.Random(2026)
    existing_names = {r[0] for r in conn.execute("SELECT name FROM employees")}
    legacy_mgrs = [r[0] for r in conn.execute(
        "SELECT id FROM employees WHERE id < ? ORDER BY id", (start,))]
    rows: list[tuple] = []
    emp_id = start - 1
    for dept, count in V2_PLAN:
        lo, hi = V2_SALARY[dept]
        for i in range(count):
            emp_id += 1
            for _ in range(200):  # deterministic collision-free naming
                name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
                if name not in existing_names:
                    existing_names.add(name)
                    break
            role = V2_ROLES[dept][i % len(V2_ROLES[dept])]
            email = name.lower().replace(" ", ".") + "@corp.example.com"
            phone = (f"+91 {rng.randrange(70, 100)} {rng.randrange(100, 1000)}"
                     f" {rng.randrange(1000, 10000)}")
            salary = rng.randrange(lo, hi, 500)
            bonus = rng.randrange(0, max(2, salary // 12), 250)
            join = date(2015, 1, 1) + timedelta(days=rng.randrange(0, 3800))
            manager = (legacy_mgrs[i % len(legacy_mgrs)]
                       if i % 3 else legacy_mgrs[(emp_id - start) % 17])
            rows.append((emp_id, name, dept, role, email, phone, salary,
                         role, bonus, join.isoformat(), manager,
                         CITIES[rng.randrange(len(CITIES))]))
    conn.executemany(
        "INSERT INTO employees (id, name, department, role, email, phone, "
        "salary, designation, bonus, join_date, manager_id, address) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.execute("DELETE FROM departments WHERE id > 5")
    heads = {}
    for r in rows:
        heads.setdefault(r[2], r[1])
    conn.executemany("INSERT INTO departments VALUES (?,?,?)",
                     [(i, d, heads.get(d, "TBD"))
                      for i, d in enumerate(NEW_DEPARTMENTS, start=6)])
    return len(rows)


def _build_org_hierarchy(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM org_hierarchy")
    conn.execute("""
        INSERT INTO org_hierarchy
        SELECT e.id, e.name, e.department, e.manager_id, m.name
        FROM employees e LEFT JOIN employees m ON m.id = e.manager_id""")


def _write_new_doc_txt_files() -> None:
    expected_slugs = {slug for _t, (_ns, slug, *_r) in DOC_FILES.items()}
    expected_slugs |= {slug for _t, (_ns, slug, *_r) in NEW_DOCS.items()}
    for title, (ns, slug, _dept, _sens, body) in NEW_DOCS.items():
        path = DOCS_DIR / ns / f"{slug}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    # prune stale txt files (renamed slugs) so the index stays canonical
    for ns_dir in DOCS_DIR.iterdir():
        if not ns_dir.is_dir():
            continue
        for p in ns_dir.glob("*.txt"):
            if p.stem not in expected_slugs:
                p.unlink()


def _insert_new_documents(conn: sqlite3.Connection) -> int:
    """50 v2 rows in the `documents` catalog (legacy 33 untouched).
    file_path points at the PDF twin; content mirrors the RAG text."""
    tiers = {"Public": "L1", "Internal": "L2", "Confidential": "L3",
             "Restricted": "L5"}
    conn.execute("DELETE FROM documents WHERE title IN (%s)"
                 % ",".join("?" * len(NEW_DOCS)), tuple(NEW_DOCS))
    n = 0
    for title, (ns, slug, dept, sens, body) in NEW_DOCS.items():
        pdf_path = f"data/pdfs/{PDF_FOLDER[ns]}/{slug}.pdf"
        conn.execute(
            "INSERT INTO documents (title, content, department, sensitivity,"
            " min_clearance, namespace, file_path) VALUES (?,?,?,?,?,?,?)",
            (title, body, dept, sens, tiers[sens], ns, pdf_path))
        n += 1
    return n


def _fake_pan(rng: random.Random) -> str:
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return ("".join(rng.choice(alpha) for _ in range(5))
            + f"{rng.randrange(1000, 9999)}" + rng.choice(alpha))


def _fill_employee_pii(conn: sqlite3.Connection) -> None:
    """FAKE-BUT-VALID-FORMAT sensitive fields for EVERY employee
    (legacy + v2). Realistic shapes so RBAC/DLP demos look real; values
    are generated, not real people's."""
    rng = random.Random(4242)
    ifsc_pool = ["HDFC0001234", "ICIC0004521", "SBIN0007152", "KKBK0008090",
                 "UTIB0002345", "YESB0004567", "AXIS0009876"]
    rows = []
    for emp_id, name in conn.execute("SELECT id, name FROM employees "
                                     "ORDER BY id"):
        r = random.Random(f"pii::{name}::{emp_id}")
        pan = _fake_pan(r)
        aadhaar = f"23{r.randrange(10**10):010d}"   # fake 2xxx series
        ifsc = ifsc_pool[emp_id % len(ifsc_pool)]
        acct = f"9{r.randrange(10**10):010d}"
        personal = name.lower().replace(" ", ".") + "@example.in"
        dob = (date(1970, 1, 1) + timedelta(days=r.randrange(0, 11000)))
        code = f"TN{emp_id:05d}"
        rows.append((emp_id, code, pan, aadhaar, ifsc, acct, personal,
                     dob.isoformat()))
    conn.execute("DELETE FROM employee_pii")
    conn.executemany(
        "INSERT OR REPLACE INTO employee_pii (emp_id, emp_code, pan, "
        "aadhaar, bank_ifsc, bank_account, personal_email, date_of_birth) "
        "VALUES (?,?,?,?,?,?,?,?)", rows)


def _build_document_acl(conn: sqlite3.Connection) -> None:
    """Role x document matrix DERIVED from the live RBAC policy, so the
    ACL table can never drift from what the engine enforces."""
    from src.governance.rbac import all_namespaces, known_roles, get_policy
    ns_all = set(all_namespaces())
    conn.execute("DELETE FROM document_acl")
    docs = conn.execute("SELECT doc_id, namespace, sensitivity, title "
                        "FROM documents").fetchall()
    for role in known_roles():
        pol = get_policy(role)
        granted = set(pol.allowed_namespaces)
        for d in docs:
            can_read = d["namespace"] in granted
            # download: readable AND not a restricted tier
            can_download = can_read and d["sensitivity"] in (
                "Public", "Internal")
            conn.execute("INSERT INTO document_acl VALUES (?,?,?,?)",
                         (d["doc_id"], role, int(can_read),
                          int(can_download)))
    # sanity: trap namespace is granted to nobody
    for d in docs:
        if d["namespace"] == "trap_docs":
            got = conn.execute(
                "SELECT COUNT(*) FROM document_acl WHERE doc_id=? AND "
                "can_read=1", (d["doc_id"],)).fetchone()[0]
            assert got == 0, "trap doc readable by some role!"
    assert ns_all, "rbac policy exposed no namespaces"


def _build_document_versions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM document_versions")
    conn.executemany("INSERT OR REPLACE INTO document_versions VALUES "
                     "(?,?,?,?,?,?,?)", DOC_VERSIONS)


def _build_data_classification(conn: sqlite3.Connection) -> None:
    rows = [
        ("employees", "salary", "Confidential", 0,
         "column-policy protected; visible to whitelisted roles only"),
        ("employees", "bonus", "Confidential", 0,
         "column-policy protected"),
        ("employees", "email", "Internal", 1, "work contact"),
        ("employees", "phone", "Internal", 1, "work contact"),
        ("employees", "address", "Internal", 1, "home city"),
        ("employee_pii", "pan", "Restricted", 1,
         "direct identifier; chatbot-structurally-blind table"),
        ("employee_pii", "aadhaar", "Restricted", 1,
         "direct identifier; chatbot-structurally-blind table"),
        ("employee_pii", "bank_ifsc", "Restricted", 1, "financial"),
        ("employee_pii", "bank_account", "Restricted", 1, "financial"),
        ("employee_pii", "personal_email", "Confidential", 1, "PII"),
        ("employee_pii", "date_of_birth", "Confidential", 1, "PII"),
        ("executives", "annual_salary", "Restricted", 0, "compensation"),
        ("executives", "stock_options", "Restricted", 0, "compensation"),
        ("executives", "performance_bonus", "Restricted", 0,
         "compensation"),
        ("users", "password_hash", "Restricted", 0,
         "bcrypt; never selectable via governed SQL"),
        ("users", "clearance", "Confidential", 0, "governance metadata"),
        ("documents", "content", "Internal", 0, "RAG corpus"),
        ("companies", "company_pan", "Internal", 0,
         "public registry number"),
        ("companies", "gstin", "Internal", 0, "public registry number"),
    ]
    conn.execute("DELETE FROM data_classification")
    conn.executemany("INSERT INTO data_classification VALUES (?,?,?,?,?)",
                     rows)


def _build_retention_rules(conn: sqlite3.Connection) -> None:
    rows = [
        ("policy", 7, "archive then purge after review",
         "company record-keeping standard"),
        ("contract", 8, "archive; purge 8y after expiry",
         "Limitation Act / MCA records"),
        ("payroll", 8, "restricted archive; purge 8y after exit",
         "labour and tax law"),
        ("invoice", 8, "restricted archive; purge after audit window",
         "GST Act records"),
        ("recruitment", 1, "purge CVs of non-hired candidates",
         "DPDP Act 2023 purpose limitation"),
        ("visitor_log", 0.25, "rolling 90-day purge",
         "facility security standard"),
        ("training_record", 3, "purge after superseding cycle",
         "compliance evidence"),
        ("audit_log", 7, "hash-chained archive; legal-hold override",
         "security policy"),
    ]
    conn.execute("DELETE FROM retention_rules")
    conn.executemany("INSERT INTO retention_rules VALUES (?,?,?,?)", rows)


# ==================================================================== PDF
_SENS_COLOR = {"Public": "#2e7d32", "Internal": "#1565c0",
               "Confidential": "#e65100", "Restricted": "#b71c1c"}
_FOLDERS = {"hr": "HR", "engineering": "Engineering",
            "sales_marketing": "Sales & Marketing", "finance": "Finance",
            "executive": "Executive", "it": "IT", "legal": "Legal",
            "operations": "Operations", "trap_decoys": "Decoy (trap)"}


def _hindi_png(body: str, out_png: Path, title: str) -> None:
    """Complex-script page rendering: reportlab cannot shape Devanagari,
    so Hindi pages are rasterised via PIL + raqm (correct matras and
    conjuncts) with the FreeSans Devanagari font."""
    from PIL import Image, ImageDraw, ImageFont
    W, H, margin = 1240, 1754, 90          # A4 @150dpi
    font = ImageFont.truetype(
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf", 30)
    tfont = ImageFont.truetype(
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf", 40)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    y = margin
    d.text((margin, y), title, font=tfont, fill="#1a237e", language="hi")
    y += 70
    done = False
    for raw in body.splitlines():
        if done:
            break
        line, lines = raw.strip(), []
        while line:
            cut = len(line)
            while cut > 1 and d.textlength(line[:cut], font=font,
                                           language="hi") > W - 2 * margin:
                cut -= 2
            lines.append(line[:cut])
            line = line[cut:].lstrip()
        for ln in lines or [""]:
            d.text((margin, y), ln, font=font, fill="#212121",
                   language="hi")
            y += 44
            if y > H - margin:
                done = True
                break
    img.save(out_png)


def _write_pdf(title: str, slug: str, sens: str, body: str,
               out_dir: Path) -> Path:
    """Styled A4 PDF twin of a catalog document (English + shaped Hindi)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (BaseDocTemplate, Frame, Image,
                                    PageTemplate, Paragraph, Spacer)

    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{slug}.pdf"
    band = _FOLDERS.get(out_dir.name, out_dir.name)
    width = A4[0] - 44 * mm

    def _decorate(canv, _doc):
        canv.saveState()
        canv.setFillColor(colors.HexColor(_SENS_COLOR[sens]))
        canv.rect(0, A4[1] - 14, A4[0], 14, stroke=0, fill=1)
        canv.setFont("Helvetica-Bold", 8)
        canv.setFillColor(colors.white)
        canv.drawString(22 * mm, A4[1] - 10,
                        f"{sens.upper()}  |  {band}  |  TechNova Solutions")
        canv.drawRightString(A4[0] - 22 * mm, A4[1] - 10, "DEMO DATASET")
        canv.setFont("Helvetica", 8)
        canv.setFillColor(colors.HexColor("#616161"))
        canv.drawString(22 * mm, 10 * mm,
                        "Fake data for the SecureLLM-Enterprise demo - "
                        "not a real company document")
        canv.drawRightString(A4[0] - 22 * mm, 10 * mm, f"{slug}.pdf")
        canv.restoreState()

    doc = BaseDocTemplate(str(out), pagesize=A4, leftMargin=22 * mm,
                          rightMargin=22 * mm, topMargin=20 * mm,
                          bottomMargin=18 * mm, title=title,
                          author="TechNova Solutions")
    doc.addPageTemplates([PageTemplate(id="p", frames=[
        Frame(doc.leftMargin, doc.bottomMargin, width,
              A4[1] - 40 * mm, id="f")], onPage=_decorate)])

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("t", parent=styles["Title"], fontSize=17,
                        spaceAfter=2, textColor=colors.HexColor("#1a237e"))
    sub = ParagraphStyle("s", parent=styles["Normal"], fontSize=9.5,
                         textColor=colors.HexColor(_SENS_COLOR[sens]),
                         spaceAfter=10)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=11.5,
                        spaceBefore=8, spaceAfter=3,
                        textColor=colors.HexColor("#283593"))
    body_style = ParagraphStyle("b", parent=styles["Normal"], fontSize=9.8,
                                leading=14.2)

    story = [Paragraph(title, h1),
             Paragraph(f"{band} &middot; classification: {sens}", sub)]
    png = None
    if slug.endswith("_hi"):                     # shaped Hindi page
        png = out_dir / f"_{slug}_page.png"
        _hindi_png(body, png, title)
        story.append(Image(str(png), width=width,
                           height=width * 1754 / 1240))
    else:
        for para in body.split("\n\n"):
            para = para.strip()
            if not para:
                continue
            lines = para.splitlines()
            first = lines[0].strip()
            if len(lines) > 1 and len(first) < 64 and first.endswith(")"):
                story.append(Paragraph(first, h2))
                text = " ".join(x.strip() for x in lines[1:])
            else:
                text = " ".join(x.strip() for x in lines)
            story.append(Paragraph(text, body_style))
            story.append(Spacer(1, 3))
    doc.build(story)
    if png is not None:                  # unlink only AFTER build (lazy IO)
        png.unlink(missing_ok=True)
    return out


def write_pdfs() -> int:
    """PDF twin for every catalog document (legacy 33 + v2 50 = 83)."""
    import sqlite3
    conn = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    live = {t: (ns, sens) for t, ns, sens in conn.execute(
        "SELECT title, namespace, sensitivity FROM documents")}
    conn.close()
    n = 0
    for title, (ns, slug, _dept, sens, body) in \
            {**DOC_FILES, **NEW_DOCS}.items():
        if title in live:                # live catalog row wins
            ns, sens = live[title]
        _write_pdf(title, slug, sens, body, PDF_DIR / PDF_FOLDER[ns])
        n += 1
    return n


# =================================================================== Excel
def _sheet(wb, name: str, headers: list[str], rows: list[list],
           widths: list[float] | None = None) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    ws = wb.create_sheet(name[:31])
    head_fill = PatternFill("solid", fgColor="1A237E")
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=c, value=h)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = head_fill
        cell.alignment = Alignment(horizontal="center")
    for r, row in enumerate(rows, 2):
        for c, v in enumerate(row, 1):
            ws.cell(row=r, column=c, value=v)
    ws.freeze_panes = "A2"
    widths = widths or [max(12, len(str(h)) + 2) for h in headers]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = min(w, 46)
    ws.auto_filter.ref = ws.dimensions


def write_excels() -> int:
    """12 workbooks generated FROM the live database + deterministic
    operational data, so cross-department values always agree with SQL."""
    import sqlite3
    from openpyxl import Workbook
    rng = random.Random(77)
    EXCEL_DIR.mkdir(parents=True, exist_ok=True)
    ro = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    ro.row_factory = sqlite3.Row
    emps = ro.execute(
        "SELECT id, name, department, role, designation, email, phone, "
        "salary, join_date, address FROM employees ORDER BY id").fetchall()
    pii = {r["emp_id"]: r for r in ro.execute("SELECT * FROM employee_pii")}

    def band(s: int) -> str:
        return ("Band A" if s < 80000 else "Band B" if s < 110000
                else "Band C" if s < 140000 else "Band D")

    # 1. employee master -----------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    _sheet(wb, "Employee Master",
           ["emp_id", "emp_code", "name", "department", "role", "email",
            "phone", "salary_band", "join_date", "location"],
           [[e["id"], pii[e["id"]]["emp_code"], e["name"], e["department"],
             e["role"], e["email"], e["phone"], band(e["salary"]),
             e["join_date"], e["address"]] for e in emps],
           widths=[8, 12, 18, 13, 18, 30, 18, 12, 12, 20])
    wb.save(EXCEL_DIR / "employee_master.xlsx")

    # 2. salary register (monthly payroll) -------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    _sheet(wb, "Salary Register 2026-09",
           ["emp_id", "name", "department", "basic", "hra", "variable",
            "gross", "tds"],
           [[e["id"], e["name"], e["department"],
             round(e["salary"] * 0.5), round(e["salary"] * 0.4),
             e["salary"] - round(e["salary"] * 0.9), e["salary"],
             round(e["salary"] * 0.10)] for e in emps])
    wb.save(EXCEL_DIR / "salary_register.xlsx")

    # 3. leave balance ------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    _sheet(wb, "Leave Balance",
           ["emp_id", "name", "department", "earned", "availed", "balance",
            "carried_forward"],
           [[e["id"], e["name"], e["department"], 24,
             (av := rng.randrange(2, 20)), 24 - av, av] for e in emps])
    wb.save(EXCEL_DIR / "leave_balance.xlsx")

    # 4. attendance log (September 2026 sample) -------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    att = []
    for e in emps[:60]:
        for dd in range(1, 29):
            st = ("P", "P", "P", "P", "WFH", "P", "P", "L", "P")[
                rng.randrange(9)]
            att.append([e["id"], e["name"], f"2026-09-{dd:02d}", st,
                        "9:0%d" % rng.randrange(0, 9)])
    _sheet(wb, "Attendance Sep 2026",
           ["emp_id", "name", "date", "status", "in_time"], att)
    wb.save(EXCEL_DIR / "attendance_log.xlsx")

    # 5. expense claims ------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    cats = ["Travel", "Hotel", "Meals", "Client entertainment", "Office"]
    claims = [[f"EXP-2026-{i:04d}", rng.choice(emps)["name"],
               rng.choice(emps)["department"], rng.choice(cats),
               rng.randrange(800, 45000, 50),
               rng.choice(["approved", "pending", "approved", "rejected"])]
              for i in range(1, 81)]
    _sheet(wb, "Expense Claims",
           ["claim_id", "employee", "department", "category", "amount_inr",
            "status"], claims)
    wb.save(EXCEL_DIR / "expense_claims.xlsx")

    # 6. vendor list ------------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    vend = [[f"VND-{i:03d}", f"Vendor {i} Services Pvt Ltd",
             rng.choice(["IT", "Facilities", "Travel", "Legal",
                         "Marketing"]),
             rng.choice(["Net 30", "Net 45", "Net 60"]),
             f"2026-0{rng.randrange(1, 10)}-{rng.randrange(10, 28):02d}",
             rng.choice(["active", "active", "under review"])]
            for i in range(1, 26)]
    _sheet(wb, "Vendor List",
           ["vendor_id", "vendor_name", "category", "payment_terms",
            "contract_renewal", "status"], vend)
    wb.save(EXCEL_DIR / "vendor_list.xlsx")

    # 7. asset inventory ----------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    assets = []
    for i, e in enumerate(emps, 1):
        assets.append([f"AST-{i:05d}", "Laptop",
                       rng.choice(["ThinkPad T14", "MacBook Pro 14",
                                   "ThinkPad X1", "Dell Latitude 5440"]),
                       e["id"], e["name"], e["department"],
                       rng.choice(["issued", "issued", "in-repair"]),
                       f"202{rng.randrange(3, 6)}"])
    for i in range(40):
        assets.append([f"AST-9{i:04d}",
                       rng.choice(["Monitor", "Phone", "License", "Dock"]),
                       rng.choice(["24in UHD", "iPhone 15",
                                   "JetBrains All", "USB-C dock"]),
                       None, "Shared pool",
                       rng.choice(["IT", "Operations", "HR"]),
                       "issued", "2025"])
    _sheet(wb, "Asset Inventory",
           ["asset_id", "asset_type", "model", "assigned_emp_id",
            "assigned_to", "department", "state", "procure_year"], assets)
    wb.save(EXCEL_DIR / "asset_inventory.xlsx")

    # 8. project tracker ------------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    projects = [
        ["PRJ-01", "Atlas - client portal", "Tech", "Vikram Singh",
         "in progress", "Q3 2026"],
        ["PRJ-02", "SOC 2 Type II readiness", "IT", "Farhan Bhatt",
         "in progress", "Q4 2026"],
        ["PRJ-03", "DPDP compliance uplift", "Legal", "Gauri Deshpande",
         "in progress", "Q4 2026"],
        ["PRJ-04", "Payroll consolidation", "Finance", "Meera Iyer",
         "completed", "Q2 2026"],
        ["PRJ-05", "Campus hiring FY27", "HR", "Anjali Verma",
         "in progress", "Q4 2026"],
        ["PRJ-06", "Bengaluru floor 4 expansion", "Operations", "Mohan Iyer",
         "planned", "Q1 2027"],
        ["PRJ-07", "Brand refresh", "Marketing", "Nandini Rao",
         "in progress", "Q3 2026"],
        ["PRJ-08", "CRM migration wave 2", "Business", "Rahul Joshi",
         "in progress", "Q4 2026"],
        ["PRJ-09", "Zero-trust network phase 2", "IT", "Kavya Menon",
         "planned", "Q1 2027"],
        ["PRJ-10", "Data warehouse cost cut", "Tech", "Arun Mehta",
         "completed", "Q2 2026"],
    ]
    _sheet(wb, "Project Tracker",
           ["project_id", "project", "department", "owner", "status",
            "target"], projects)
    wb.save(EXCEL_DIR / "project_tracker.xlsx")

    # 9. sales pipeline ----------------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    stages = ["qualification", "proposal", "negotiation", "won", "lost"]
    pipe = [[f"OPP-{i:04d}",
             rng.choice(["Acme Retail", "Bharat Logistics", "Zenith Health",
                         "Orion Manufacturing", "Sunrise Foods",
                         "Nimbus Telecom", "Quantum Insurance",
                         "Deccan Motors"]),
             rng.choice(["Platform licence", "Managed services",
                         "Implementation"]),
             rng.choice(stages), rng.randrange(5, 250) * 100000,
             "Business"]
            for i in range(1, 31)]
    _sheet(wb, "Sales Pipeline",
           ["opportunity_id", "account", "offering", "stage", "value_inr",
            "owning_department"], pipe)
    wb.save(EXCEL_DIR / "sales_pipeline.xlsx")

    # 10. training records ---------------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    tr = []
    courses = ["Security awareness 2026", "POSH certification",
               "DPDP fundamentals", "First aid", "Incident response drill"]
    for e in emps[:80]:
        for c in rng.sample(courses, rng.randrange(1, 4)):
            tr.append([e["id"], e["name"], e["department"], c,
                       f"2026-0{rng.randrange(1, 10)}-"
                       f"{rng.randrange(10, 28):02d}",
                       rng.choice(["completed", "completed", "due"])])
    _sheet(wb, "Training Records",
           ["emp_id", "name", "department", "course", "date", "status"], tr)
    wb.save(EXCEL_DIR / "training_records.xlsx")

    # 11. holiday calendar 2026 -------------------------------------------------------------------------
    wb = Workbook(); wb.remove(wb.active)
    hol = [["2026-01-26", "Republic Day", "National"],
           ["2026-03-04", "Holi", "National"],
           ["2026-04-01", "Annual closes", "Company"],
           ["2026-05-01", "Labour Day", "Regional"],
           ["2026-08-15", "Independence Day", "National"],
           ["2026-09-14", "Ganesh Chaturthi", "Regional"],
           ["2026-10-02", "Gandhi Jayanti", "National"],
           ["2026-11-08", "Diwali", "National"],
           ["2026-12-25", "Christmas", "National"]]
    _sheet(wb, "Holidays 2026", ["date", "holiday", "type"], hol)
    wb.save(EXCEL_DIR / "holiday_calendar.xlsx")

    # 12. org chart data ------------------------------------------------------------------------------------
    org = ro.execute("SELECT emp_name, department, reports_to_name FROM "
                     "org_hierarchy ORDER BY department, emp_name") \
        .fetchall()
    wb = Workbook(); wb.remove(wb.active)
    _sheet(wb, "Org Chart Data",
           ["employee", "department", "reports_to"],
           [[o["emp_name"], o["department"], o["reports_to_name"] or "-"]
            for o in org])
    wb.save(EXCEL_DIR / "org_chart_data.xlsx")
    ro.close()
    return 12


# =================================================================== Images
def write_images() -> int:
    """Deterministic placeholder images: logo, org chart, floor plan and
    GST-style invoice scans (OCR/RAG demo fodder)."""
    from PIL import Image, ImageDraw, ImageFont
    rng = random.Random(99)
    bold = "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf"
    reg = "/usr/share/fonts/truetype/freefont/FreeSans.ttf"
    f_big = ImageFont.truetype(bold, 120)
    f_mid = ImageFont.truetype(bold, 34)
    f_sm = ImageFont.truetype(reg, 22)
    (IMG_DIR / "invoices").mkdir(parents=True, exist_ok=True)

    # 1. logo -----------------------------------------------------------------
    img = Image.new("RGB", (900, 300), "#0e1a3a")
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((40, 60, 240, 240), 40, fill="#ffc107")
    d.text((90, 95), "TN", font=f_big, fill="#0e1a3a")
    d.text((280, 95), "TechNova Solutions", font=f_mid, fill="white")
    d.text((280, 150), "Secure enterprise platforms", font=f_sm,
           fill="#9fa8da")
    img.save(IMG_DIR / "logo.png")

    # 2. org chart -----------------------------------------------------------------
    img = Image.new("RGB", (1600, 900), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 20), "TechNova - Org Chart (top levels)", font=f_mid,
           fill="#1a237e")

    def box(x, y, text, fill="#e8eaf6", w=230, h=74):
        d.rounded_rectangle((x, y, x + w, y + h), 10, fill=fill,
                            outline="#3949ab", width=2)
        for li, ln in enumerate(text.split("\n")):
            d.text((x + 12, y + 12 + li * 26), ln, font=f_sm,
                   fill="#212121")

    def line(x1, y1, x2, y2):
        d.line((x1, y1, x2, y2), fill="#3949ab", width=2)

    box(680, 90, "Meera Nair - CEO", "#ffc107")
    heads = [("Rajesh Kumar\nCOO", 80), ("Priya Sharma\nCTO", 400),
             ("Anjali Verma\nHR", 720), ("Meera Iyer\nFinance", 1040),
             ("Gauri Deshpande\nLegal", 1300)]
    for label, x in heads:
        line(795, 164, x + 115, 260)
        box(x, 260, label)
    leaf = {"Priya Sharma\nCTO": ["Platform", "Security", "SRE", "QA"],
            "Anjali Verma\nHR": ["TA", "HRBP", "PeopleOps"],
            "Meera Iyer\nFinance": ["FP&A", "AP/AR", "Treasury"],
            "Rajesh Kumar\nCOO": ["Operations", "Facilities"],
            "Gauri Deshpande\nLegal": ["Contracts", "Compliance"]}
    for label, x in heads:
        for j, k in enumerate(leaf[label]):
            line(x + 115, 334, x + 52 + j * 90, 430)
            box(x + 10 + j * 90, 430, k, "#e3f2fd", w=84, h=50)
    d.text((30, 820), "Generated placeholder - matches org_hierarchy table",
           font=f_sm, fill="#757575")
    img.save(IMG_DIR / "org_chart.png")

    # 3. floor plan ---------------------------------------------------------------------
    img = Image.new("RGB", (1400, 900), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 20), "Bengaluru HQ - Floor 3 (placeholder)", font=f_mid,
           fill="#1a237e")
    rooms = [("Platform Eng", 60, 100, 380, 320),
             ("Security Eng", 420, 100, 660, 320),
             ("Meeting A", 700, 100, 900, 260),
             ("Meeting B", 940, 100, 1140, 260),
             ("Server room", 1180, 100, 1340, 260),
             ("Open desks 1-40", 60, 360, 900, 640),
             ("HR suite", 940, 300, 1340, 460),
             ("Finance suite", 940, 500, 1340, 660),
             ("Cafeteria", 60, 680, 660, 840),
             ("Reception", 700, 680, 1340, 840)]
    for name, x1, y1, x2, y2 in rooms:
        fill = ("#ffcdd2" if name == "Server room"
                else "#e8f5e9" if name == "Reception" else "#e3f2fd")
        d.rectangle((x1, y1, x2, y2), fill=fill, outline="#455a64",
                    width=3)
        d.text((x1 + 14, y1 + 14), name, font=f_sm, fill="#263238")
    img.save(IMG_DIR / "floor_plan.png")

    # 4. invoice scans ----------------------------------------------------------------------
    for n in (1, 2, 3):
        img = Image.new("RGB", (1240, 900), "#fdfdfb")
        d = ImageDraw.Draw(img)
        d.rectangle((0, 0, 1240, 6), fill="#1a237e")
        d.text((60, 40), "TechNova Solutions Pvt Ltd", font=f_mid,
               fill="#1a237e")
        d.text((60, 90), "Tower B, Prestige Tech Park, Bengaluru 560103",
               font=f_sm, fill="#444444")
        d.text((60, 125), "GSTIN: 29ABCDE1234F1Z5   PAN: ABCDE1234F",
               font=f_sm, fill="#444444")
        d.text((900, 60), "TAX INVOICE", font=f_mid, fill="#b71c1c")
        d.text((900, 110), f"INV-2026-000{n}", font=f_sm, fill="#212121")
        d.text((60, 220), f"Bill to:  Vendor {n} Services Pvt Ltd",
               font=f_sm, fill="#212121")
        d.text((60, 255), f"Date: 2026-0{n}-1{n}   PO: PO-2026-0{n:03d}",
               font=f_sm, fill="#212121")
        d.line((60, 320, 1180, 320), fill="#1a237e", width=3)
        for i, h in enumerate(["#", "Description", "Qty", "Rate", "Amount"]):
            d.text((60 + i * 230, 340), h, font=f_sm, fill="#1a237e")
        total = 0
        for r in range(4):
            qty = rng.randrange(1, 6)
            rate = rng.randrange(15, 90) * 1000
            amt = qty * rate
            total += amt
            d.text((60, 390 + r * 45), f"{r + 1}", font=f_sm)
            d.text((290, 390 + r * 45), rng.choice(
                ["Managed platform subscription", "Implementation sprint",
                 "Support retainer", "Training workshop"]), font=f_sm)
            d.text((750, 390 + r * 45), str(qty), font=f_sm)
            d.text((830, 390 + r * 45), f"{rate:,}", font=f_sm)
            d.text((1000, 390 + r * 45), f"{amt:,}", font=f_sm)
        d.line((60, 590, 1180, 590), fill="#1a237e", width=3)
        d.text((860, 610), f"Total: INR {total:,}", font=f_mid,
               fill="#b71c1c")
        d.text((60, 700), "Scanned-document placeholder for the OCR/RAG "
               "demo - fake data", font=f_sm, fill="#757575")
        for _ in range(140):                       # faint scan artefacts
            d.point((rng.randrange(1240), rng.randrange(900)),
                    fill="#d7d7d2")
        img.save(IMG_DIR / "invoices" / f"inv_2026_000{n}.png")
    return 6


# ================================================================= Metadata
def write_metadata_yamls() -> int:
    """Human-auditable YAML exports mirroring the SQL glue tables."""
    import sqlite3
    ro = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    ro.row_factory = sqlite3.Row
    META_DIR.mkdir(parents=True, exist_ok=True)

    docs = [dict(r) for r in ro.execute(
        "SELECT doc_id, title, department, sensitivity, min_clearance, "
        "namespace, file_path FROM documents ORDER BY doc_id")]
    for d in docs:
        slug = Path(d["file_path"]).stem
        d["txt_path"] = f"data/docs/{d['namespace']}/{slug}.txt"
        d["is_trap_decoy"] = slug in TRAP_SLUGS
    META_DIR.joinpath("document_metadata.yaml").write_text(
        yaml.safe_dump({"documents": docs}, sort_keys=False,
                       allow_unicode=True), encoding="utf-8")

    acl: dict[str, list[dict]] = {}
    for r in ro.execute("SELECT doc_id, role, can_read, can_download "
                        "FROM document_acl ORDER BY doc_id, role"):
        acl.setdefault(f"doc_{r['doc_id']}", []).append(
            {k: r[k] for k in ("role", "can_read", "can_download")})
    META_DIR.joinpath("document_acl.yaml").write_text(
        yaml.safe_dump(acl, sort_keys=False), encoding="utf-8")

    cls = [dict(r) for r in ro.execute(
        "SELECT schema_table, column_name, classification, pii, note "
        "FROM data_classification ORDER BY schema_table, column_name")]
    META_DIR.joinpath("data_classification.yaml").write_text(
        yaml.safe_dump({"fields": cls}, sort_keys=False), encoding="utf-8")

    ret = [dict(r) for r in ro.execute(
        "SELECT doc_type, retention_years, purge_policy, legal_basis "
        "FROM retention_rules ORDER BY doc_type")]
    META_DIR.joinpath("retention_rules.yaml").write_text(
        yaml.safe_dump({"rules": ret}, sort_keys=False), encoding="utf-8")

    row = ro.execute("SELECT * FROM companies WHERE id=1").fetchone()
    META_DIR.joinpath("company_profile.yaml").write_text(
        yaml.safe_dump(dict(row) if row else {}, sort_keys=False,
                       allow_unicode=True), encoding="utf-8")
    ro.close()
    return 5


# ================================================================ orchestr
def extend_everything() -> dict:
    """SQL extension + all artifacts, in dependency order."""
    report = extend_database()
    report["pdfs"] = write_pdfs()
    report["excels"] = write_excels()
    report["images"] = write_images()
    report["metadata_yamls"] = write_metadata_yamls()
    return report


def print_report(report: dict) -> None:
    import sqlite3
    conn = sqlite3.connect(f"file:{COMPANY_DB}?mode=ro", uri=True)
    counts = {}
    for t in ("employees", "departments", "documents", "companies",
              "locations", "teams", "org_hierarchy", "employee_pii",
              "document_acl", "data_classification", "retention_rules",
              "document_versions"):
        counts[t] = conn.execute(
            f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608
    conn.close()
    print("== dataset v2 row counts ==")
    for t, c in counts.items():
        print(f"  {t:22s} {c}")
    print("== artifacts ==")
    for k in ("pdfs", "excels", "images", "metadata_yamls"):
        print(f"  {k:22s} {report.get(k, '-')}")

