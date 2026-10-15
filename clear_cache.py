#!/usr/bin/env python3
"""
Quick utility to clear all stale cached analyses from the SQLite database.
Run this ONCE after applying the app.py fixes to ensure fresh API calls.

Usage: python clear_cache.py
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "threat_cache.db"

if not DB_PATH.exists():
    print(f"[INFO] No database found at {DB_PATH} — nothing to clear.")
else:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cache")
    count = cur.fetchone()[0]
    cur.execute("DELETE FROM cache")
    conn.commit()
    conn.close()
    print(f"[OK] Cleared {count} cached analysis record(s) from {DB_PATH}")
    print("[INFO] The next analysis will fetch fresh data from all APIs.")
