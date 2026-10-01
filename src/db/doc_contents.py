"""Single source of truth for the RAG document corpus (33 documents).

Every entry: title -> (namespace, slug, department, sensitivity, body).
The seed script (a) writes each body to data/docs/<ns>/<slug>.txt so the
vector store can ingest it, and (b) inserts a matching `documents` row with
its sensitivity tier and minimum clearance - the catalog auditors review.

Content rules (deliberate, so Layer 6 never has a false-positive excuse):
- no PII, no money figures outside exec_docs, no "bonus" outside exec_docs,
- no card-shaped digit runs, no injection phrases.
"""

_WFH = """Work-From-Home Policy (Tech)
============================
Engineers may work from home up to 3 days per week. Core collaboration hours
are 11:00-15:00 IST. Fully remote arrangements require CTO approval and are
reviewed every 6 months. Home-office stipend is INR 15,000 per year, paid with
the March salary cycle."""

_LEAVE = """Leave Policy (HR)
=================
Employees earn 24 days of paid leave per year. Unused leave up to 6 days may be
carried forward. Sick leave requires a medical note beyond 3 continuous days.
Maternity leave is 26 weeks; paternity leave is 10 working days. Apply in the
HR portal at least 7 days in advance for planned leave."""

_COMPC = """Compensation Confidentiality Policy (HR)
========================================
Salary information is confidential. It is shared strictly on a need-to-know
basis: HR partners and the executive team. Individual salaries must never be
discussed in public channels or exposed to other departments. Compensation data
is processed only for payroll and legal purposes (DPDP Act 2023, purpose
limitation). Any suspected leak must be reported to security within 24 hours."""

_SECURE = """Secure Coding Standard (Tech)
=============================
All production code must pass SAST and secret scanning before merge. Secrets
belong in the vault, never in source. Every API endpoint must enforce
authentication and role-based authorization server-side. Logs must not contain
personal data. Dependencies are pinned and scanned weekly."""

_BOARD = """Board Bonus Summary FY26 (Executive only)
=========================================
Approved executive bonus pool for FY26:
- Meera Nair (CEO): $2,400,000
- James Dsouza (CFO): $1,700,000
- Anita Rao (CTO): $1,600,000
Distribution is handled by the compensation committee. These figures are
board-confidential until the annual filing."""

DOC_FILES: dict[str, tuple[str, str, str, str, str]] = {
    # title: (namespace, slug, department, sensitivity, body)
    "Leave Policy": ("hr_docs", "leave_policy", "HR", "Internal", _LEAVE),
    "Compensation Confidentiality": ("hr_docs", "comp_confidentiality", "HR",
                                     "Confidential", _COMPC),
    "Work From Home Policy": ("tech_docs", "wfh_policy", "Tech", "Internal",
                              _WFH),
    "Secure Coding Standard": ("tech_docs", "secure_coding", "Tech",
                               "Internal", _SECURE),
    "Board Bonus Memo": ("exec_docs", "board_bonus", "Executive", "Restricted",
                         _BOARD),

    "Employee Handbook": ("hr_docs", "employee_handbook", "HR", "Internal", """
Employee Handbook (HR)
======================
Welcome to the company. Every employee receives a grade band, a reporting
manager and an annual development plan. The handbook covers working hours,
dress norms, office facilities and the exit process. Notice periods are 30
days for individual contributors and 60 days for leads and managers.
Employees are expected to complete mandatory compliance training within 30
days of joining and once every year after that."""),

    "Code of Conduct": ("hr_docs", "code_of_conduct", "HR", "Internal", """
Code of Conduct (HR)
====================
We act with integrity toward colleagues, customers and partners. Harassment,
discrimination and retaliation are zero-tolerance offences. Conflicts of
interest must be declared to your manager and the compliance team. Intellectual
property created during employment belongs to the company. Violations are
handled by the ethics committee with a documented, appealable process."""),

    "Benefits Overview": ("hr_docs", "benefits_overview", "HR", "Internal", """
Benefits Overview (HR)
======================
Full-time employees are covered by the group medical plan, term life cover and
accident insurance from day one. The wellness allowance reimburses gym or
yoga memberships up to the annual cap. Learning and certification costs are
reimbursed on manager approval. Counseling sessions through the employee
assistance program are free and strictly confidential."""),

    "Parental Leave": ("hr_docs", "parental_leave", "HR", "Internal", """
Parental Leave (HR)
===================
Birth mothers receive 26 weeks of paid leave, extendable by 8 weeks unpaid.
Non-birth parents receive 10 working days, usable within 6 months of birth.
Adoptive parents of a child under 12 months receive 12 weeks. Flexible
return-to-work offers reduced hours for the first month after a long leave.
Managers may not deny statutory parental leave under any circumstance."""),

    "Grievance Procedure": ("hr_docs", "grievance_procedure", "HR", "Internal",
"""
Grievance Procedure (HR)
========================
Raise concerns first with your reporting manager, unless the concern involves
that manager. The HR partner acknowledges every grievance within 2 working
days and closes it, with a written outcome, within 21 days. Sexual harassment
complaints follow the POSH committee process, which runs independently.
Retaliation against a complainant is itself a conduct violation."""),

    "Referral Policy": ("hr_docs", "referral_policy", "HR", "Internal", """
Referral Policy (HR)
====================
Employees earn a referral award when a referred candidate completes 90 days
in role. Referrals for business and engineering roles pay one tier; critical
and leadership roles pay a higher tier. Employees may not refer close family
members or anyone in their own reporting chain. The award is paid in the
next monthly cycle after the qualifying date."""),

    "Attendance Policy": ("hr_docs", "attendance_policy", "HR", "Internal", """
Attendance Policy (HR)
======================
Standard office hours are 09:30 to 18:15 with a flexible start window.
Attendance is tracked for compliance, not micro-management: regularisation
requests must be filed within 7 days. Three unregularised absence instances
in a quarter trigger a manager conversation. Chronic irregularity may affect
appraisal ratings but never statutory entitlements."""),

    "Workplace Safety": ("hr_docs", "workplace_safety", "HR", "Internal", """
Workplace Safety (HR)
=====================
Emergency exits, assembly points and first-aid kits are marked on every floor.
Fire drills run twice a year and participation is mandatory. Report any hazard
through the safety portal; reports are triaged within one working day. The
facility team maintains CCTV for safety only, and footage retention is 30
days under the privacy policy."""),

    "Deployment Runbook": ("tech_docs", "deployment_runbook", "Tech",
                           "Internal", """
Deployment Runbook (Tech)
=========================
Production deploys go through the blue-green pipeline with automated rollback
on health-check failure. Every change needs a reviewed pull request, a passing
CI gate and a linked ticket. Deploys are frozen during the weekend on-call
window unless the incident commander approves. Post-deploy, watch error rate
and p99 latency for 30 minutes before closing the change."""),

    "Incident Response Plan": ("tech_docs", "incident_response", "Tech",
                               "Internal", """
Incident Response Plan (Tech)
=============================
Severity 1 means customer-impacting outage or suspected data breach: page the
on-call, open a war room and notify the security duty officer within 15
minutes. Contain first, eradicate second, then recover and verify. Every Sev1
gets a blameless post-mortem within 5 working days with tracked action items.
Regulatory notification decisions are made by the security council, not by
individual engineers."""),

    "Architecture Overview": ("tech_docs", "architecture_overview", "Tech",
                              "Internal", """
Architecture Overview (Tech)
============================
The platform runs as microservices behind an API gateway, with Kafka for event
streaming and PostgreSQL as the primary store. Services communicate over mTLS
with workload identities issued at deploy time. The AI assistant is isolated
in its own security zone and reaches data only through the governance
pipeline. Capacity headroom is reviewed monthly against the growth forecast."""),

    "On-call Handbook": ("tech_docs", "oncall_handbook", "Tech", "Internal", """
On-call Handbook (Tech)
=======================
The rotation is weekly, primary and shadow, handed over every Monday with a
written summary of open risks. Acknowledge pages within 5 minutes; escalate
to the secondary after 15 without progress. Keep the runbook links updated
before your rotation starts, not during an incident. Compensation for weekend
on-call follows the finance policy on additional duty hours."""),

    "Access Management Standard": ("tech_docs", "access_management", "Tech",
                                   "Internal", """
Access Management Standard (Tech)
=================================
Access is granted by role, reviewed quarterly, and revoked on the day of role
change. Production access requires hardware-token MFA and just-in-time
elevation with an expiry. Break-glass credentials are sealed, monitored and
rotated after every use. No human or service account may bypass the central
audit log for any reason."""),

    "Disaster Recovery and Backup": ("tech_docs", "dr_backup_policy", "Tech",
                                     "Internal", """
Disaster Recovery and Backup (Tech)
===================================
Backups are encrypted, incremental and tested by a quarterly restore drill.
Recovery point objective is 15 minutes for tier-1 stores; recovery time
objective is 60 minutes. The DR site runs in a separate region with
independent credentials. Restore results are signed off by the platform lead
and filed with the audit team."""),

    "Q1 Strategy": ("business_docs", "q1_strategy", "Business",
                    "Confidential", """
Q1 Strategy (Business)
======================
Q1 focuses on expansion in mid-market accounts and a bundled offering for the
manufacturing vertical. The pipeline target grows by a double-digit percentage
over the previous quarter, weighted toward multi-year contracts. Partner-led
deals get priority enablement support. This plan is commercially sensitive:
share externally only under NDA and never through public channels."""),

    "Competitor Analysis": ("business_docs", "competitor_analysis", "Business",
                            "Confidential", """
Competitor Analysis (Business)
==============================
Three competitors dominate the mid-market segment; two are competing on
price, one on integration depth. Their public roadmaps suggest a growing push
into compliance automation, which validates our differentiated controls.
Win rates improved after the packaging change introduced last year. Position
against the price-led players by quantifying total cost of ownership rather
than discounting."""),

    "Pricing Policy": ("business_docs", "pricing_policy", "Business",
                       "Confidential", """
Pricing Policy (Business)
=========================
List prices are published per seat with volume tiers at fixed breakpoints.
Discounts above the standard band need regional sales-director approval, and
above the extended band need the pricing committee. Evaluation licences run
for a fixed term and convert only through a signed order form. Currency and
tax treatment follow the finance booking rules for each region."""),

    "Sales Playbook": ("business_docs", "sales_playbook", "Business",
                       "Internal", """
Sales Playbook (Business)
=========================
Qualify every opportunity on need, authority, timing and fit before demoing.
The standard cycle is discovery, technical validation, commercial review and
procurement. Use the CRM stage definitions exactly; forecasting accuracy is
a shared team metric. Escalate security-questionnaire blockers to the
pre-sales solutions team instead of promising custom work."""),

    "Partner Policy": ("business_docs", "partner_policy", "Business",
                       "Internal", """
Partner Policy (Business)
=========================
Partners are tiered by certified skills and sourced revenue. Deal
registration protects the first registered partner for a fixed window.
Partners may not subcontract delivery of security-critical workloads. Joint
marketing requires brand review and must not imply exclusive rights. Tier
reviews run twice a year on objective criteria."""),

    "Market Research 2026": ("business_docs", "market_research_2026",
                             "Business", "Internal", """
Market Research 2026 (Business)
===============================
Demand for governed AI assistants keeps accelerating as regulators publish
enterprise guidance. Buyers now shortlist vendors on auditability, data
residency and role-based access rather than model benchmarks. Budget owners
consolidate point tools into platform purchases. The mid-market remains the
fastest-growing segment for the next four quarters."""),

    "FY27 Budget Summary": ("finance_docs", "fy27_budget_summary", "Finance",
                            "Confidential", """
FY27 Budget Summary (Finance)
=============================
The FY27 plan prioritises platform reliability, security tooling and compliance
certification. Headcount growth is front-loaded in engineering, flat in
general and administrative functions. Cloud spend carries a committed-use
discount negotiated last quarter. Variance above the approved band requires
finance-council sign-off before commitment."""),

    "Expense Policy": ("finance_docs", "expense_policy", "Finance",
                       "Internal", """
Expense Policy (Finance)
========================
Submit expenses within 30 days of purchase with itemised receipts. Domestic
travel books economy; international long-haul books premium economy with
pre-approval. Client entertainment needs a business purpose and attendee
list. Cash advances settle with the final report; unresolved advances move
to payroll deduction after due notice."""),

    "Procurement Policy": ("finance_docs", "procurement_policy", "Finance",
                           "Internal", """
Procurement Policy (Finance)
============================
Purchases above the threshold need three comparative quotes and a signed
purchase order before work starts. Vendor onboarding includes sanctions
screening and a data-protection review when personal data is involved.
Renewals are reviewed 90 days ahead for value and utilisation. No team may
engage a vendor informally to bypass the controls."""),

    "Cashflow Forecast Q1": ("finance_docs", "cashflow_forecast_q1",
                             "Finance", "Confidential", """
Cashflow Forecast Q1 (Finance)
==============================
Collections concentrate in the last month of the quarter, so the treasury
buffer covers the early-weeks trough. Vendor payment runs are scheduled to
protect the minimum liquidity band. The forecast assumes no early debt
reduction this quarter. Treasury movements above the delegated limit need
dual authorisation by the finance lead and the CFO office."""),

    "Board Minutes Q1": ("exec_docs", "board_minutes_q1", "Executive",
                         "Restricted", """
Board Minutes Q1 (Executive only)
=================================
The board reviewed the annual filing calendar and the audit plan. Risk
appetite was reaffirmed, with explicit attention to third-party and AI
governance exposure. The compensation committee confirmed the executive
reward outcomes recorded separately in the restricted annex. Minutes are
distributed to directors only and embargoed until the next meeting."""),

    "MA Pipeline": ("exec_docs", "ma_pipeline", "Executive", "Restricted", """
M&A Pipeline (Executive only)
=============================
Two targets are in active diligence: a regional services firm and a
compliance-automation startup. The working group includes corporate
development, legal and information security. Deal terms, valuations and
integration drafts are board-restricted until signing. Leaks to press or
staff would be a material governance breach with disciplinary consequence."""),

    "Succession Plan": ("exec_docs", "succession_plan", "Executive",
                        "Restricted", """
Succession Plan (Executive only)
================================
Every C-level seat has a named ready-now or ready-soon successor with a
development plan. Emergency succession covers absence within 48 hours.
The plan is refreshed after each board cycle and held by the CHRO and the
board secretary. Contents are personal-data sensitive and must not be
summarised outside the restricted distribution."""),

    "Investor Update": ("exec_docs", "investor_update", "Executive",
                        "Restricted", """
Investor Update (Executive only)
================================
The quarterly investor letter drafts the narrative before the earnings call:
growth, margin discipline and governance investments. Forward statements
follow the disclosure policy and legal review. Undisclosed material
information must never reach analysts, press or internal chat. The final
version is published by the investor-relations office only."""),
}


def catalog_rows() -> list[tuple[str, str, str, str, str]]:
    """(title, content, department, sensitivity, namespace) in stable order."""
    ns_dept = {"hr_docs": "HR", "tech_docs": "Tech",
               "business_docs": "Business", "finance_docs": "Finance",
               "exec_docs": "Executive"}
    rows = []
    for title, (ns, _slug, _dept, _sens, body) in DOC_FILES.items():
        rows.append((title, body, ns_dept[ns], _sens, ns))
    return rows
