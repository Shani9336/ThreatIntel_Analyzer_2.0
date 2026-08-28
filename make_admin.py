import sqlite3
conn = sqlite3.connect('threat_cache.db')
conn.execute("UPDATE users SET role='admin' WHERE email='shaniyadav777am@gmail.com'")
conn.commit()
conn.close()
print("✅ Admin role set successfully!")
print("Now go to: http://localhost:5000/admin/logs")