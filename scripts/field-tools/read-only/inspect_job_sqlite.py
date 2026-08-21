from __future__ import annotations

import sqlite3
import sys


database, job_id = sys.argv[1:3]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    row = connection.execute(
        "SELECT id, status, current_sequence FROM automatic_jobs WHERE id = ?",
        (job_id,),
    ).fetchone()
    print(row)
finally:
    connection.close()
