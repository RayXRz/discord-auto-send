from sqlalchemy import create_engine, text
import os, secrets, sys

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")
engine = create_engine(DB_URL)

def create_keys(n):
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS register_key (
                id SERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                used BOOLEAN DEFAULT FALSE
            )
        """))
        keys = []
        for _ in range(n):
            k = secrets.token_urlsafe(9)
            try:
                conn.execute(text("INSERT INTO register_key (key, used) VALUES (:key, false)"), {"key": k})
                keys.append(k)
            except:
                pass
        conn.commit()
    return keys

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    new_keys = create_keys(n)
    print(f"{len(new_keys)} key berhasil dibuat:")
    for k in new_keys:
        print(k)
