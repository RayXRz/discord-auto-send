# generate_keys.py
import secrets

def create_key(n=1):
    from app import db, RegisterKey  # import di sini, di dalam fungsi
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
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    keys = create_key(n)
    print(f"{len(keys)} key berhasil dibuat:")
    for k in keys:
        print(k)
