import sqlite3
from typing import List, Optional
from contextlib import contextmanager
from model import ThreatLevel, Report


class ReportsRepository:
    """
    Service for managing SQLite database operations.
    
    Handles connection management, table creation, and data insertion
    for threat assessment reports.
    """
    
    def __init__(self, db_path: str = "threat_reports.db"):
        """
        Initialize the SQLite service.
        
        Args:
            db_path (str): Path to the SQLite database file. Defaults to "threat_reports.db".
        """
        self.db_path = db_path
        self._initialize_database()
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            sqlite3.Connection: Database connection object.

        """
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _initialize_database(self):
        """
        Initialize the database and create necessary tables if they don't exist.
        
        Creates:
            - report table: Stores aggregated threat level incident counts
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create report table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_level TEXT NOT NULL,
                    incidents_count INTEGER NOT NULL DEFAULT 0,
                    first_incident TIMESTAMP,
                    last_incident TIMESTAMP
                )
            """)
    
    def insert_report(self, report: Report) -> int:
        """
        Insert a threat level report into the database.
        
        Args:
            report (Report): The report object to insert.
        
        Returns:
            int: The ID of the inserted record.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO report (threat_level, incidents_count, first_incident, last_incident)
                VALUES (?, ?, ?, ?)
            """, (report.threat_level.value, report.incidents_count, report.first_incident, report.last_incident))
            return cursor.lastrowid
    
    def insert_reports_batch(self, reports: List[Report]) -> int:
        """
        Insert multiple reports in a single transaction.
        
        Args:
            reports (List[Report]): List of Report objects to insert.
        
        Returns:
            int: Number of records inserted.

        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            data = [
                (report.threat_level.value, report.incidents_count, report.first_incident, report.last_incident)
                for report in reports
            ]
            cursor.executemany("""
                INSERT INTO report (threat_level, incidents_count, first_incident, last_incident)
                VALUES (?, ?, ?, ?)
            """, data)
            return cursor.rowcount


