"""SQLite models for IP-level host tracking."""
import sqlite3
import threading
from pathlib import Path
from config import DB_PATH

_local = threading.local()

def get_db():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=30)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'shodan',
        query_tag TEXT NOT NULL,
        country TEXT NOT NULL,
        reading_number INTEGER NOT NULL,
        host_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        transport TEXT DEFAULT 'tcp',
        product TEXT DEFAULT '',
        version TEXT DEFAULT '',
        org TEXT DEFAULT '',
        asn TEXT DEFAULT '',
        hostnames TEXT DEFAULT '[]',
        vulns TEXT DEFAULT '[]',
        banner_hash TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_hosts_snapshot ON hosts(snapshot_id);
    CREATE INDEX IF NOT EXISTS idx_hosts_ip_port ON hosts(ip, port);

    CREATE TABLE IF NOT EXISTS consolidated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        query_tag TEXT NOT NULL,
        country TEXT NOT NULL,
        host_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_consolidated_unique
        ON consolidated(date, query_tag, country);

    CREATE TABLE IF NOT EXISTS consolidated_hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        consolidated_id INTEGER NOT NULL REFERENCES consolidated(id),
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        transport TEXT DEFAULT 'tcp',
        product TEXT DEFAULT '',
        org TEXT DEFAULT '',
        readings_present INTEGER DEFAULT 1,
        shodan_confirmed INTEGER DEFAULT 1,
        censys_confirmed INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0.33
    );
    CREATE INDEX IF NOT EXISTS idx_ch_consolidated ON consolidated_hosts(consolidated_id);
    CREATE INDEX IF NOT EXISTS idx_ch_ip ON consolidated_hosts(ip);

    CREATE TABLE IF NOT EXISTS changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        query_tag TEXT NOT NULL,
        country TEXT NOT NULL,
        change_type TEXT NOT NULL,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        product TEXT DEFAULT '',
        org TEXT DEFAULT '',
        confidence REAL DEFAULT 0.0,
        nmap_verified INTEGER,
        nmap_state TEXT,
        notified INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_changes_date ON changes(date, country);

    CREATE TABLE IF NOT EXISTS nmap_budget (
        date TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS censys_budget (
        date TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
    );
    """)
    db.commit()
