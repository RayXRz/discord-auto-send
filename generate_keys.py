# generate_keys.py (SQLAlchemy version)
import secrets
from app import db, RegisterKey

# generate_keys.py
def create_key(n=1):
    from app import db, RegisterKey  # import di dalam fungsi, bukan di atas
    import secrets
    keys = []
    for _ in range(n):
        while True:
            k = secrets.token_urlsafe(9)
            try:
                rk = RegisterKey(key=k, used=False)
                db.session.add(rk)
                db.session.commit()
                keys.append(k)
                break
            except Exception:
                db.session.rollback()
    return keys


if __name__ == "__main__":
    n = 1
    try:
        import sys
        if len(sys.argv) > 1:
            n = int(sys.argv[1])
    except:
        pass
    keys = create_key(n)  # <-- harus sesuai nama fungsi
    print(f"{len(keys)} key berhasil dibuat:")
    for k in keys:
        print(k)
