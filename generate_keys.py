# generate_keys.py
import sqlite3
import secrets
import sys
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

def create_keys(n):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # pastikan tabel register_key ada
    cur.execute('''
    CREATE TABLE IF NOT EXISTS register_key (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        used INTEGER DEFAULT 0
    )
    ''')
    
    keys = []
    for _ in range(n):
        k = secrets.token_urlsafe(9)  # generate key random
        try:
            cur.execute("INSERT INTO register_key (key, used) VALUES (?, 0)", (k,))
            keys.append(k)
        except sqlite3.IntegrityError:
            pass  # skip jika kebetulan key duplicate
    
    conn.commit()
    conn.close()
    return keys

if __name__ == "__main__":
    n = 1
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            print("Argumen harus angka, default 1 key akan dibuat")
    
    new_keys = create_keys(n)
    print(f"{len(new_keys)} key berhasil dibuat:")
    for k in new_keys:
        print(k)
