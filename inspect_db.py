import sqlite3

conn = sqlite3.connect("database/forensics.db")

print("EVENT COUNTS BY CASE")
for row in conn.execute("SELECT case_id, COUNT(*) FROM events GROUP BY case_id"):
    print(row)

print("\nCASE-06 EVIDENCE RECORDS")
for row in conn.execute(
    "SELECT source_type, record_count, status, uploaded_at FROM evidence_files WHERE case_id = ?",
    ("CASE-06-DIAGNOSTIC",)
):
    print(row)

print("\nEVENT TABLE SCHEMA")
for row in conn.execute("PRAGMA table_info(events)"):
    print(row)

conn.close()
