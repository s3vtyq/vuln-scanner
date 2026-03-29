"""SQLite caching for NVD API responses."""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from ..nvd.models import CVEData


class NVDCache:
    """SQLite cache for NVD API responses."""

    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "vuln-scanner"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "nvd_cache.db"
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires_at ON cve_cache(expires_at)
            """)

    @contextmanager
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def get(self, cve_id: str) -> Optional[CVEData]:
        """Get cached CVE data if not expired."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT data, expires_at FROM cve_cache WHERE cve_id = ?",
                (cve_id,)
            ).fetchone()

            if row is None:
                return None

            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.now() > expires_at:
                # Expired
                conn.execute("DELETE FROM cve_cache WHERE cve_id = ?", (cve_id,))
                conn.commit()
                return None

            data = json.loads(row["data"])
            return CVEData(**data)

    def set(self, cve_id: str, cve_data: CVEData, ttl_hours: int = 24) -> None:
        """Cache CVE data with TTL."""
        now = datetime.now()
        expires_at = now + timedelta(hours=ttl_hours)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (
                cve_id,
                json.dumps(cve_data.model_dump(mode="json")),
                now.isoformat(),
                expires_at.isoformat()
            ))
            conn.commit()

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM cve_cache WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
            conn.commit()
            return cursor.rowcount
