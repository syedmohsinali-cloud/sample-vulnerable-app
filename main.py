# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safe literal evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # Warning: This function is still potentially dangerous and should be used with caution
    # Consider using more specific, controlled functions instead of arbitrary shell commands
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Fixed insecure deserialization by using ast.literal_eval for safe evaluation (Issue 5)
    # Note: This assumes the blob contains only safe literals (strings, numbers, tuples, lists, dicts, booleans, None)
    # If more complex objects are needed, consider using a secure serialization format like JSON
    try:
        return ast.literal_eval(blob.decode('utf-8'))
    except (ValueError, SyntaxError):
        raise ValueError("Invalid or unsafe data for deserialization")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate safer calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice"))  # No longer vulnerable to SQLi
    print(run_shell("echo Hello && whoami"))  # Still potentially dangerous, use with caution
    try:
        # attempting to deserialize using the safer method
        print(deserialize_blob(b"{'key': 'value'}"))
    except Exception as e:
        print("Deserialization error:", e)

# Note: While these changes address the immediate vulnerabilities,
# there are still security concerns with this code:
# 1. The API token is still hardcoded and should be stored securely.
# 2. The database is still stored in an insecure location.
# 3. The run_shell function remains a potential security risk.
# 4. Passwords are stored in plain text, which is not recommended.
# Consider addressing these issues in future updates.