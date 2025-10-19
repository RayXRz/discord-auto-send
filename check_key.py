import os
import sqlite3
import psycopg2
from urllib.parse import urlparse

# ambil database url dari environment (kalau ada)
DB_URL = os.environ.get("DATABASE_URL")

def get_connection():
    if DB_URL:
        result = urlparse(DB_URL)
        return psycopg2.connect(
            database=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port
        )
    else:
        return sqlite3.connect("app.db")

def list_keys():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS register_key (
            id SERIAL PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            used BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()

    print("=== Semua Key ===")
    cur.execute("SELECT key, used FROM register_key")
    rows = cur.fetchall()
    if not rows:
        print("Belum ada key tersimpan.")
    else:
        for k, u in rows:
            status = "Sudah dipakai" if u else "Belum dipakai"
            print(f"{k}: {status}")

    conn.close()

def add_key(new_key):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO register_key (key) VALUES (%s)", (new_key,))
        conn.commit()
        print(f"Key '{new_key}' berhasil ditambahkan")
    except Exception as e:
        print(f"Key '{new_key}' sudah ada atau error: {e}")
    finally:
        conn.close()

def mark_used(key_to_mark):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE register_key SET used=TRUE WHERE key=%s", (key_to_mark,))
    if cur.rowcount:
        print(f"Key '{key_to_mark}' ditandai sudah dipakai")
    else:
        print(f"Key '{key_to_mark}' tidak ditemukan")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    while True:
        print("\n1. Lihat semua key\n2. Tambah key baru\n3. Tandai key sudah dipakai\n4. Keluar")
        choice = input("Pilih: ").strip()
        if choice == "1":
            list_keys()
        elif choice == "2":
            new_key = input("Masukkan key baru: ").strip()
            add_key(new_key)
        elif choice == "3":
            k = input("Key yang mau ditandai: ").strip()
            mark_used(k)
        elif choice == "4":
            break
        else:
            print("Pilihan tidak valid 😅")
