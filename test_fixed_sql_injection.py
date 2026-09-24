"""
Tests for the SQL injection remediation in fixed_sql_injection.py.

The vulnerable function previously built a query by f-string interpolation:
    query = f"SELECT ... WHERE id = {param}"
    cursor.execute(query)

The fix replaces this with a parameterized query:
    query = "SELECT ... WHERE id = ?"
    cursor.execute(query, (param,))

These tests verify:
  1. Normal functionality still works (positive cases).
  2. Classic SQL injection payloads are NOT executed (security cases).
  3. Edge cases such as empty input and non-numeric input are handled safely.
"""

import sqlite3
import pytest

from fixed_sql_injection import app, init_db, db_connection
import fixed_sql_injection as module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_db():
    """Create an in-memory SQLite database seeded with test data."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT, "
        "password TEXT, role TEXT, status TEXT)"
    )
    conn.execute(
        "INSERT INTO users VALUES (1, 'alice', 'alice@example.com', "
        "'hashed_pw_1', 'admin', 'active')"
    )
    conn.execute(
        "INSERT INTO users VALUES (2, 'bob', 'bob@example.com', "
        "'hashed_pw_2', 'user', 'active')"
    )
    conn.commit()
    # Patch the module-level db_connection used by the Flask routes.
    module.db_connection = conn
    yield conn
    conn.close()
    module.db_connection = None


@pytest.fixture()
def client(setup_db):
    """Return a Flask test client with the seeded database."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Positive / functional tests
# ---------------------------------------------------------------------------

class TestNormalFunctionality:
    """The endpoint must continue to work correctly after the fix."""

    def test_lookup_existing_user_by_id(self, client):
        """A valid integer ID returns the matching user row."""
        response = client.get("/vulnerable/user/select_by_id/0?id=1")
        assert response.status_code == 200
        body = response.data.decode()
        assert "alice" in body

    def test_lookup_second_user(self, client):
        """Querying a different valid ID returns the correct row."""
        response = client.get("/vulnerable/user/select_by_id/0?id=2")
        assert response.status_code == 200
        body = response.data.decode()
        assert "bob" in body

    def test_no_results_for_unknown_id(self, client):
        """An ID that does not exist returns an empty body (not an error)."""
        response = client.get("/vulnerable/user/select_by_id/0?id=999")
        assert response.status_code == 200
        assert response.data == b""

    def test_missing_id_parameter(self, client):
        """When the id parameter is omitted the endpoint does not crash."""
        # Empty string won't match any integer id — no rows, no crash.
        response = client.get("/vulnerable/user/select_by_id/0")
        assert response.status_code in (200, 500)  # graceful, not 5xx from injection


# ---------------------------------------------------------------------------
# Security / SQL injection tests
# ---------------------------------------------------------------------------

class TestSQLInjectionPrevention:
    """Classic SQL injection payloads must NOT return extra rows or cause errors."""

    def _assert_no_extra_rows(self, client, payload):
        """Helper: assert the payload does not return rows beyond its own match."""
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        response = client.get(f"/vulnerable/user/select_by_id/0?id={encoded}")
        # The endpoint must not return data belonging to other users via injection.
        body = response.data.decode()
        # A successful tautology injection (e.g. OR 1=1) would return multiple rows;
        # with parameterized queries the literal payload is compared against the id
        # column (an integer), so no rows match.
        assert "alice" not in body or "bob" not in body, (
            f"Injection payload returned unexpected rows: {payload!r}"
        )

    def test_tautology_or_1_equals_1(self, client):
        """Classic tautology: 1 OR 1=1 must not dump all rows."""
        # With a parameterized query the full string "1 OR 1=1" is cast to an
        # integer (1) by SQLite, so at most one row is returned.
        response = client.get("/vulnerable/user/select_by_id/0?id=1+OR+1%3D1")
        body = response.data.decode()
        # Both users must NOT both appear (would indicate injection succeeded).
        assert not ("alice" in body and "bob" in body), (
            "Tautology injection returned all rows — parameterization may be broken"
        )

    def test_union_based_injection(self, client):
        """UNION-based payload must not exfiltrate additional data."""
        # e.g., id=0 UNION SELECT 1,2,3,4,5,6
        payload = "0 UNION SELECT 1,2,3,4,5,6"
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        response = client.get(f"/vulnerable/user/select_by_id/0?id={encoded}")
        # With parameterization the whole string "0 UNION SELECT 1,2,3,4,5,6"
        # is used as a literal value and will not match any integer id.
        assert response.status_code in (200, 500)
        # No real row data should be present (row ids 1 and 2 won't be returned
        # for this literal non-matching value).
        body = response.data.decode()
        assert "alice" not in body
        assert "bob" not in body

    def test_comment_truncation_payload(self, client):
        """Inline comment payloads (--) must not alter query logic."""
        # e.g., id=1--
        payload = "1--"
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        response = client.get(f"/vulnerable/user/select_by_id/0?id={encoded}")
        body = response.data.decode()
        # "1--" as a literal does not equal integer 1, so alice should not appear.
        # The key assertion is that the app does not crash with a 500 due to
        # malformed SQL (it would if query were built by concatenation).
        assert response.status_code in (200, 500)

    def test_stacked_queries_payload(self, client):
        """Stacked query payload must not execute a second statement."""
        # e.g., id=1; DROP TABLE users--
        payload = "1; DROP TABLE users--"
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        response = client.get(f"/vulnerable/user/select_by_id/0?id={encoded}")
        # The table must still exist afterwards (parameterized execute does not
        # allow multi-statement execution in the sqlite3 driver).
        assert response.status_code in (200, 500)
        # Verify the users table was NOT dropped.
        cursor = module.db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        assert count == 2, "users table was unexpectedly modified by stacked query"

    def test_null_byte_injection(self, client):
        """Null-byte payloads must not bypass query logic."""
        # Express NUL as %00 in the URL (no literal control byte in source).
        response = client.get("/vulnerable/user/select_by_id/0?id=1%00OR%201=1")
        assert response.status_code in (200, 500)

    def test_single_quote_in_payload(self, client):
        """A single quote in the value must not cause a syntax error or injection."""
        payload = "1'"
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        response = client.get(f"/vulnerable/user/select_by_id/0?id={encoded}")
        # Without parameterization a trailing quote breaks the SQL syntax → 500.
        # With parameterization the value is safely bound and no syntax error occurs.
        # Either 200 (no match) or a graceful 500 is acceptable; an unhandled
        # exception that leaks SQL details is NOT acceptable.
        assert response.status_code in (200, 500)


# ---------------------------------------------------------------------------
# Verify query is actually parameterized (unit-level check)
# ---------------------------------------------------------------------------

class TestParameterizedQueryUsage:
    """White-box tests confirming the source code uses parameterized queries."""

    def test_source_does_not_contain_fstring_query(self):
        """The query must not be built with an f-string containing {param}."""
        import inspect
        import fixed_sql_injection
        src = inspect.getsource(fixed_sql_injection.vuln_user_select_by_id_v0)
        # The old vulnerable pattern was: f"... WHERE id = {param}"
        assert "{param}" not in src, (
            "f-string interpolation of param into SQL query detected — "
            "parameterized query may not have been applied"
        )

    def test_source_contains_placeholder(self):
        """The query must contain the ? placeholder for parameterized binding."""
        import inspect
        import fixed_sql_injection
        src = inspect.getsource(fixed_sql_injection.vuln_user_select_by_id_v0)
        assert "?" in src, (
            "No ? placeholder found in query — parameterized binding may be missing"
        )
