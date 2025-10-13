import sqlite3

DB_PATH = "app.db"  # path ke database

def list_keys():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # pastikan tabel register_key ada
    cur.execute("""CREATE TABLE IF NOT EXISTS register_key (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    used INTEGER DEFAULT 0
                )""")
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
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO register_key (key) VALUES (?)", (new_key,))
        conn.commit()
        print(f"Key '{new_key}' berhasil ditambahkan")
    except sqlite3.IntegrityError:
        print(f"Key '{new_key}' sudah ada")
    finally:
        conn.close()

def mark_used(key_to_mark):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE register_key SET used=1 WHERE key=?", (key_to_mark,))
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
