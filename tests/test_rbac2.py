"""Wave 2.4 - RBAC 2.0: row scope, self-scope, whitelisted aggregates.

Pinned guarantees (the acceptance scenarios):
  - "my salary" works for roles WITHOUT salary in their column whitelist,
    answered from the caller's OWN row (bound-parameter username query);
    the reply flows through L6 with soft shape rules yielding for own data
    while hard rules + faithfulness stay armed;
  - "Arun Mehta's salary" from the same role is STILL an official
    AUTHZ_FIELD denial (self-scope never widens to others);
  - "average salary per department" routes to the whitelisted AVG builder
    for roles whose whitelist allows it, and is officially denied for
    roles whose whitelist does not;
  - aggregate identifiers are whitelist-checked; no user input is ever
    interpolated.
"""
import pytest

from src.governance import rbac
from src.rag import retriever
from tests.conftest import login


# ---------- unit: self-scope query builder ----------------------------------
def test_build_self_query_whitelists_and_binds():
    pol = rbac.get_policy("HR_Employee")
    sql, params, _conn = rbac.build_self_query(
        pol, ["id", "name", "department", "role", "salary", "email", "phone"])
    assert "FROM employees" in sql
    assert "username = ?" in sql            # bound parameter, never inline
    assert "salary" in sql and "email" in sql and "phone" in sql
    assert "LIMIT 1" in sql
    # a column outside (identity + self_scope) can never slip in
    sql2, _p, _c = rbac.build_self_query(pol, ["address", "salary"])
    assert "address" not in sql2 and "salary" in sql2


def test_build_self_query_denied_without_grant():
    pol = rbac.get_policy("default")        # no self_scope
    with pytest.raises(rbac.PermissionDenied) as ei:
        rbac.build_self_query(pol)
    assert ei.value.code.value == "AUTHZ_ROW"


def test_run_self_query_returns_own_row():
    pol = rbac.get_policy("HR_Employee")
    rows = rbac.run_self_query(pol, "hr_emp1")
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "Suresh Patel"
    assert isinstance(row["salary"], (int, float)) and row["salary"] > 0
    assert row["email"] == "suresh.patel@corp.example.com"
    assert rbac.run_self_query(pol, "nobody_user") == []


# ---------- unit: whitelisted aggregates ------------------------------------
def test_run_aggregate_avg_salary_per_department():
    pol = rbac.get_policy("Finance_Manager")
    rows = rbac.run_aggregate(pol, "employees", "avg", column="salary",
                              group_by="department")
    assert rows and len(rows) >= 2          # several departments
    for r in rows:
        assert "department" in r and "avg_salary" in r
        assert isinstance(r["avg_salary"], (int, float))


def test_run_aggregate_count_needs_no_sensitive_column():
    pol = rbac.get_policy("HR_Manager")     # salary allowed, contact not
    rows = rbac.run_aggregate(pol, "employees", "count", group_by="department")
    assert rows


def test_run_aggregate_denies_out_of_whitelist():
    pol = rbac.get_policy("HR_Employee")    # salary NOT allowed AND the
    # employees base table is not granted either (public view only)
    with pytest.raises(rbac.PermissionDenied) as ei:
        rbac.run_aggregate(pol, "employees", "avg", column="salary",
                           group_by="department")
    assert ei.value.code.value == "AUTHZ_TABLE"
    # on a granted table, a restricted COLUMN is the denial reason
    with pytest.raises(rbac.PermissionDenied) as ei2:
        rbac.run_aggregate(pol, "employees_public_view", "avg",
                           column="salary", group_by="department")
    assert ei2.value.code.value == "AUTHZ_FIELD"
    with pytest.raises(rbac.PermissionDenied):     # table not granted at all
        rbac.run_aggregate(rbac.get_policy("Tech_Engineer"), "executives",
                           "avg", column="bonus")
    with pytest.raises(rbac.PermissionDenied):     # metric whitelist
        rbac.run_aggregate(rbac.get_policy("Finance_Manager"), "employees",
                           "sum", column="salary")


# ---------- API: the acceptance scenarios end to end ------------------------
def test_hr_employee_my_salary_answered(client):
    """THE 2.4 acceptance: self-scope makes MY salary visible even though
    the role's table whitelist has no salary column."""
    hr_emp = login(client, "hr_emp1", "HrE@123")
    body = client.post("/chat", headers=hr_emp,
                       json={"message": "What is my salary?"}).json()
    assert body.get("denied_code") is None, body["response"]
    assert any(ch.isdigit() for ch in body["response"])
    l4 = next(t for t in body["meta"]["trace"] if t["layer"] == "L4")
    assert l4["result"]["rows"] == 1


def test_tech_engineer_my_salary_not_redacted(client):
    """Self-scoped replies bypass SOFT role DLP (own data), but the answer
    stays faithful: a hallucinated figure is still removed by L6."""
    eng = login(client, "tech_eng1", "TechE@123")
    body = client.post("/chat", headers=eng,
                       json={"message": "What is my salary?"}).json()
    assert body.get("denied_code") is None
    assert any(ch.isdigit() for ch in body["response"])


def test_colleague_salary_still_denied(client):
    """Self-scope never widens: someone else's salary stays denied."""
    hr_emp = login(client, "hr_emp1", "HrE@123")
    body = client.post("/chat", headers=hr_emp,
                       json={"message": "What is Neha Gupta's "
                                        "salary?"}).json()
    assert body["denied_code"] == "AUTHZ_FIELD"


def test_finance_manager_average_salary_per_department(client):
    fin = login(client, "fin_manager", "FinM@123")
    body = client.post("/chat", headers=fin,
                       json={"message": "What is the average salary per "
                                        "department?"}).json()
    assert body.get("denied_code") is None, body["response"]
    assert any(ch.isdigit() for ch in body["response"])
    l4 = next(t for t in body["meta"]["trace"] if t["layer"] == "L4")
    assert l4["result"]["rows"] >= 2        # one aggregate row per dept


def test_hr_employee_average_salary_officially_denied(client):
    """Aggregates over a restricted column are denied via the Denial
    Engine - the aggregate path never widens access."""
    hr_emp = login(client, "hr_emp1", "HrE@123")
    body = client.post("/chat", headers=hr_emp,
                       json={"message": "What is the average salary per "
                                        "department?"}).json()
    assert body["denied_code"] == "AUTHZ_FIELD"
    assert "aggregate on 'salary'" in body["response"]


def test_count_per_department_works_without_salary(client):
    """COUNT needs no sensitive column: Tech_Engineer gets headcounts."""
    eng = login(client, "tech_eng1", "TechE@123")
    body = client.post("/chat", headers=eng,
                       json={"message": "How many employees per "
                                        "department?"}).json()
    assert body.get("denied_code") is None, body["response"]
    assert any(ch.isdigit() for ch in body["response"])


def test_field_intent_exempts_self_scope_fields():
    """The Wave 1.1 field-intent check exempts self-scope grants so 'my X'
    flows to the self path instead of an official denial."""
    pol = rbac.get_policy("Tech_Employee")
    assert rbac.field_intent_violation(pol, "What is my salary?") is None
    assert rbac.field_intent_violation(
        pol, "What is Arun Mehta's salary?") is not None
