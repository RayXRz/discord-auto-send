# generate_keys.py (SQLAlchemy version)
import secrets
from app import db, RegisterKey

def create_keys(n=1):
    new_keys = []
    for _ in range(n):
        k = secrets.token_urlsafe(9)
        try:
            rk = RegisterKey(key=k)
            db.session.add(rk)
            db.session.flush()  # biar dapat id, tapi belum commit
            new_keys.append(k)
        except Exception:
            db.session.rollback()  # kalau ada duplicate key
    db.session.commit()
    return new_keys

if __name__ == "__main__":
    n = 1
    try:
        import sys
        if len(sys.argv) > 1:
            n = int(sys.argv[1])
    except:
        pass
    keys = create_keys(n)
    print(f"{len(keys)} key berhasil dibuat:")
    for k in keys:
        print(k)
