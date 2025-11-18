#!/usr/bin/env python3
"""
Database Verification Script

This script verifies that the threat_reports database contains the expected data:
- Retrieves all records from the report table
- Checks that all threat levels are represented
- Prints all data in a formatted manner
"""

import sqlite3
from typing import List, Dict, Set
from model import ThreatLevel
from datetime import datetime


def get_all_reports(db_path: str = "threat_reports.db") -> List[Dict]:
    """
    Retrieve all reports from the database.
    
    Args:
        db_path (str): Path to the SQLite database file.
    
    Returns:
        List[Dict]: List of all report records as dictionaries.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, threat_level, incidents_count, first_incident, last_incident
        FROM report
        ORDER BY 
            CASE threat_level
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END
    """)
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def verify_threat_levels(reports: List[Dict]) -> tuple[bool, Set[str]]:
    """
    Verify that all threat levels are present in the reports.
    
    Args:
        reports (List[Dict]): List of report records.
    
    Returns:
        tuple: (is_complete, missing_levels)
            - is_complete (bool): True if all threat levels are present
            - missing_levels (Set[str]): Set of missing threat levels
    """
    expected_levels = {level.value for level in ThreatLevel}
    present_levels = {report['threat_level'] for report in reports}
    missing_levels = expected_levels - present_levels
    
    return len(missing_levels) == 0, missing_levels


def format_timestamp(timestamp: int) -> str:
    """
    Format a Unix timestamp to a human-readable string.
    
    Args:
        timestamp (int): Unix timestamp in milliseconds.
    
    Returns:
        str: Formatted date string.
    """
    if timestamp is None:
        return "N/A"
    # Convert milliseconds to seconds
    return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')


def print_reports(reports: List[Dict]):
    """
    Print all reports in a formatted table.
    
    Args:
        reports (List[Dict]): List of report records.
    """
    if not reports:
        print("No reports found in the database.")
        return
    
    print("\n" + "=" * 100)
    print("THREAT ASSESSMENT REPORTS")
    print("=" * 100)
    print(f"{'ID':<5} {'Threat Level':<15} {'Incidents':<12} {'First Incident':<20} {'Last Incident':<20}")
    print("-" * 100)
    
    total_incidents = 0
    for report in reports:
        print(f"{report['id']:<5} "
              f"{report['threat_level']:<15} "
              f"{report['incidents_count']:<12} "
              f"{format_timestamp(report['first_incident']):<20} "
              f"{format_timestamp(report['last_incident']):<20}")
        total_incidents += report['incidents_count']
    
    print("-" * 100)
    print(f"Total Records: {len(reports)}")
    print(f"Total Incidents: {total_incidents}")
    print("=" * 100 + "\n")


def main():
    """
    Main function to verify database contents.
    """
    print("\n🔍 Starting Database Verification...")
    print("=" * 100)
    
    try:
        # Retrieve all reports
        reports = get_all_reports()
        
        if not reports:
            print("❌ ERROR: No reports found in the database!")
            print("   Please run the ETL pipeline first to populate the database.")
            return
        
        # Verify all threat levels are present
        is_complete, missing_levels = verify_threat_levels(reports)
        
        print(f"\n📊 Database Statistics:")
        print(f"   Total Records: {len(reports)}")
        print(f"   Expected Threat Levels: {len(ThreatLevel)}")
        print(f"   Present Threat Levels: {len(set(r['threat_level'] for r in reports))}")
        
        if is_complete:
            print(f"\n✅ SUCCESS: All threat levels are represented in the database!")
        else:
            print(f"\n⚠️  WARNING: Missing threat levels: {', '.join(missing_levels)}")
        
        # Print all reports
        print_reports(reports)
        
        # Summary by threat level
        print("\n📈 Summary by Threat Level:")
        print("-" * 50)
        threat_summary = {}
        for report in reports:
            level = report['threat_level']
            if level not in threat_summary:
                threat_summary[level] = 0
            threat_summary[level] += report['incidents_count']
        
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = threat_summary.get(level, 0)
            bar = "█" * (count // max(1, max(threat_summary.values()) // 50))
            print(f"{level:<10} {count:>5} incidents {bar}")
        print("-" * 50)
        
        if is_complete:
            print("\n✅ Database verification completed successfully!")
        else:
            print("\n⚠️  Database verification completed with warnings!")
        
    except sqlite3.OperationalError as e:
        print(f"\n❌ ERROR: Could not connect to database!")
        print(f"   {str(e)}")
        print("   Make sure the database file exists and the ETL pipeline has been run.")
    except Exception as e:
        print(f"\n❌ ERROR: Unexpected error during verification!")
        print(f"   {str(e)}")


if __name__ == "__main__":
    main()

