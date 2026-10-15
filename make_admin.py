import sys, os, sqlite3

email = sys.argv[1] if len(sys.argv) > 1 else "shaniyadav777am@gmail.com"
db_url = os.environ.get("DATABASE_URL")

if db_url:
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("UPDATE users SET role='admin' WHERE email=%s", (email,))
        affected = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ PostgreSQL error: {e}")
        sys.exit(1)
else:
    db_path = os.path.join(os.path.dirname(__file__), 'threat_cache.db')
    conn = sqlite3.connect(db_path)
    cur = conn.execute("UPDATE users SET role='admin' WHERE email=?", (email,))
    affected = cur.rowcount
    conn.commit()
    conn.close()

if affected > 0:
    print(f"✅ Admin role granted successfully to: {email}")
    print("Now go to: http://localhost:5000/admin/logs")
else:
    print(f"⚠️  No user found with email: {email}")
    print("Please make sure you have registered/signed up with this email first at /signup")