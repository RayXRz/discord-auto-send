import sqlite3

conn = sqlite3.connect("app.db")  # ganti sesuai nama file db kamu
cur = conn.cursor()

# liat semua tabel
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("tables:", cur.fetchall())

# liat struktur tabel (misal tabel bernama settings)
cur.execute("PRAGMA table_info(settings)")
for col in cur.fetchall():
    print(col)

for table in ["user", "user_token", "user_setting"]:
    print(f"\n=== isi tabel {table} ===")
    cur.execute(f"SELECT * FROM {table}")
    rows = cur.fetchall()
    for row in rows:
        print(row)
    if not rows:
        print("(kosong)")


conn.close()


