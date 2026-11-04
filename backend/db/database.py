"""
database.py — SQLite persistence layer for phishing detector scan history.

Uses Python's built-in sqlite3 — no ORM required.
All queries use parameterised statements to prevent SQL injection.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)


def _get_db_path() -> Path:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from backend.config import config
    return Path(config.DATABASE_PATH)


def get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection with row_factory set to Row."""
    db_path = _get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Create tables if they do not already exist."""
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT    NOT NULL,
                label       INTEGER NOT NULL,
                label_text  TEXT    NOT NULL,
                confidence  REAL    NOT NULL,
                phishing_probability REAL NOT NULL,
                model_name  TEXT,
                scanned_at  TEXT    NOT NULL,
                features_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_history (scanned_at DESC);
            CREATE INDEX IF NOT EXISTS idx_label       ON scan_history (label);

            CREATE TABLE IF NOT EXISTS training_runs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                trained_at      TEXT    NOT NULL,
                best_model      TEXT,
                accuracy        REAL,
                precision_score REAL,
                recall          REAL,
                f1_score        REAL,
                roc_auc         REAL,
                n_train         INTEGER,
                n_test          INTEGER,
                meta_json       TEXT
            );
        """)
        conn.commit()
        log.info("Database initialised at %s", _get_db_path())
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------

def save_scan(result: Dict[str, Any]) -> int:
    """Persist a scan result. Returns the new row id."""
    import json
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scan_history
               (domain, label, label_text, confidence, phishing_probability,
                model_name, scanned_at, features_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["domain"],
                result["label"],
                result["label_text"],
                result["confidence"],
                result["phishing_probability"],
                result.get("model_name", ""),
                datetime.now(timezone.utc).isoformat(),
                json.dumps(result.get("features", {})),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_history(page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """Return paginated scan history, newest first."""
    offset = (page - 1) * per_page
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        rows = conn.execute(
            """SELECT id, domain, label, label_text, confidence,
                      phishing_probability, model_name, scanned_at
               FROM scan_history
               ORDER BY scanned_at DESC
               LIMIT ? OFFSET ?""",
            (per_page, offset),
        ).fetchall()
        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
            "items": [dict(r) for r in rows],
        }
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Return a single scan record by ID, or None."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_scan(scan_id: int) -> bool:
    """Delete a scan record. Returns True if a row was deleted."""
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    """Return aggregate statistics for the dashboard."""
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        phishing = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE label = 1"
        ).fetchone()[0]
        legitimate = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE label = 0"
        ).fetchone()[0]
        avg_conf = conn.execute(
            "SELECT AVG(confidence) FROM scan_history"
        ).fetchone()[0] or 0.0

        # Recent 7 days
        daily_rows = conn.execute(
            """SELECT DATE(scanned_at) as day,
                      COUNT(*) as total,
                      SUM(CASE WHEN label=1 THEN 1 ELSE 0 END) as phishing,
                      SUM(CASE WHEN label=0 THEN 1 ELSE 0 END) as legitimate
               FROM scan_history
               WHERE scanned_at >= DATETIME('now', '-7 days')
               GROUP BY day
               ORDER BY day ASC"""
        ).fetchall()

        return {
            "total_scans": total,
            "phishing_count": phishing,
            "legitimate_count": legitimate,
            "detection_rate": round(phishing / total, 4) if total > 0 else 0.0,
            "avg_confidence": round(avg_conf, 4),
            "daily_trend": [dict(r) for r in daily_rows],
        }
    finally:
        conn.close()


def record_training_run(meta: Dict[str, Any]) -> None:
    """Store a training run record (called after successful train.py run)."""
    import json
    conn = get_connection()
    try:
        winner = meta.get("winner_metrics", {})
        conn.execute(
            """INSERT INTO training_runs
               (trained_at, best_model, accuracy, precision_score, recall,
                f1_score, roc_auc, n_train, n_test, meta_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                meta.get("trained_at", datetime.utcnow().isoformat()),
                meta.get("best_model", ""),
                winner.get("accuracy"),
                winner.get("precision"),
                winner.get("recall"),
                winner.get("f1_score"),
                winner.get("roc_auc"),
                meta.get("n_train"),
                meta.get("n_test"),
                json.dumps(meta),
            ),
        )
        conn.commit()
    finally:
        conn.close()
