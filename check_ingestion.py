import sqlite3

conn = sqlite3.connect("database/forensics.db")
conn.row_factory = sqlite3.Row

rows = conn.execute(
    "SELECT source_type, file_name, record_count, status, errors "
    "FROM evidence_files WHERE case_id = ?",
    ("CASE-06-DIAGNOSTIC",)
).fetchall()

print("Evidence file records:", len(rows))

for row in rows:
    print(dict(row))

conn.close()
