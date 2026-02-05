import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("scan_results.db")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            scan_mode TEXT NOT NULL,
            tools TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(
    *,
    target: str,
    target_type: str,
    scan_mode: str,
    tools: list[str],
    created_at: str,
    result: dict[str, Any],
) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scan_runs (target, target_type, scan_mode, tools, created_at, result_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            target_type,
            scan_mode,
            ",".join(tools),
            created_at,
            json.dumps(result, ensure_ascii=False),
        ),
    )
    conn.commit()
    run_id = cursor.lastrowid
    conn.close()
    return int(run_id)


def get_scan(run_id: int) -> dict[str, Any] | None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        return None

    return {
        "id": row["id"],
        "target": row["target"],
        "target_type": row["target_type"],
        "scan_mode": row["scan_mode"],
        "tools": row["tools"].split(",") if row["tools"] else [],
        "created_at": row["created_at"],
        "result": json.loads(row["result_json"]),
    }
