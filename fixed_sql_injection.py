import sqlite3
from flask import Flask, request, Response

app = Flask(__name__)

# Database connection variable
db_connection = None


# ============================================================
# The single intentionally-vulnerable endpoint (SQL injection)
# ============================================================

@app.route("/vulnerable/user/select_by_id/0")
def vuln_user_select_by_id_v0():
    """User lookup by ID using a parameterized query to prevent SQL injection"""
    param = request.args.get("id", "")
    # Use a parameterized query: the placeholder ? is bound to param by the
    # database driver, so user-supplied input is never interpreted as SQL.
    query = "SELECT id, username, email, password, role, status FROM users WHERE id = ?"
    try:
        cursor = db_connection.cursor()
        cursor.execute(query, (param,))
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        return Response("Database error", status=500)


def init_db():
    """Initialize database connection"""
    global db_connection
    try:
        db_connection = sqlite3.connect(":memory:", check_same_thread=False)
        print("Database initialized")
    except Exception as e:
        print(f"DB connection error: {e}")


if __name__ == "__main__":
    init_db()
    print("Starting server with 1 vulnerable endpoint...")
    app.run(host="0.0.0.0", port=8080, debug=True)
