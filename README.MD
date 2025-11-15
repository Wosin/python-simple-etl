# Python Threat Aggregation ETL

## Overview

This repository contains a groundwork for an ETL (Extract, Transform, Load) pipeline that processes login activity data to assess security threats. The system reads login activity from CSV files, evaluates the threat level based on predefined criteria, and stores the results in a SQLite database.

## Project Structure

```
python-simple-etl/
├── db/                    # Database service layer
│   └── sqlite_service.py  # SQLite database operations
├── etl/                   # ETL pipeline logic
├── model/                 # Data models
│   ├── access_details.py  # Access details model
│   ├── exceptions.py      # Custom exceptions
│   ├── report.py          # Report model
│   └── threat_level.py    # Threat level enumeration
├── services/              # Business logic services
│   └── ThreatAssessmentService.py  # Threat assessment logic
└── login_activity.csv     # Sample login activity data
```

## Your Task
Your task is to implement a simple Python ETL pipeline that will generate threat assessment reports based on login activity data. The ETL pipeline should perform the following steps:
1. Read the login activity data from a CSV file.
2. Enrich data by assessing the threat level for each login attempt based using defined service.
3. Aggregate the threat levels to generate a summary report.
4. Store the generated report in a SQLite database using defined database service.