# Phishing Email Automation System

## Overview

The **Phishing Email Automation System** is a Django-based security automation system designed to process incoming emails, extract Indicators of Compromise (IOCs), perform threat intelligence analysis, calculate a risk score, classify the email, and generate a final security report.

The complete system is divided into three main components:

1. **Email Gateway**
2. **Risk Engine**
3. **Report Generator**

The system automates the complete flow from receiving an email to generating the final security analysis report.

---

# System Workflow

```text
Incoming Email
      ↓
Email Gateway
      ↓
Email Reading and Data Extraction
      ↓
Email Validation
      ↓
Risk Engine
      ↓
IOC Extraction
      ↓
Threat Intelligence Analysis
      ↓
Risk Calculation
      ↓
Risk Classification
      ↓
Final JSON
      ↓
Report Generator
      ↓
Final Security Report
```

---

# High-Level Architecture

<img width="709" height="396" alt="HIGHLEVEL_DESIGN" src="https://github.com/user-attachments/assets/234c8634-2364-4856-8df6-abdd8ea4648d" />

----Detailed Flow----
<img width="758" height="392" alt="HIGHLEVEL_DETAILEDFLOW" src="https://github.com/user-attachments/assets/1683673c-f16c-48d9-a6dd-540a60a6c8bd" />


The high-level architecture represents the complete communication flow between the major components of the system.

```text
Gmail Inbox
      ↓
Email Reader
      ↓
Django Gateway
      ↓
Risk Engine API
      ↓
Risk Analysis
      ↓
Report Generator
      ↓
MySQL / SMTP
      ↓
Final Security Report
```

The high-level architecture consists of the following major components:

### 1. Gmail Inbox

The system receives incoming emails from the Gmail inbox.

### 2. Email Reader

The Email Reader connects to Gmail using IMAP and performs the following operations:

* Reads incoming emails.
* Downloads attachments.
* Extracts URLs.
* Extracts email content.
* Builds standardized email JSON.

### 3. Django Gateway

The Django Gateway receives the email JSON and performs:

* Email validation.
* Email data storage.
* Attachment handling.
* URL extraction.
* Payload preparation.
* Forwarding data to the Risk Engine.

### 4. Risk Engine API

The Risk Engine receives the email data through the API and performs security analysis.

### 5. Risk Analysis

The Risk Analysis module performs:

* IOC extraction.
* Threat intelligence analysis.
* Risk calculation.
* Risk classification.

### 6. Report Generator

The Report Generator receives the final analysis and:

* Validates the final JSON.
* Generates the security report.
* Stores report information.
* Sends the final report through SMTP.

### 7. MySQL / SMTP

The final report information can be stored and delivered through email.

---

# Low-Level Architecture


<img width="1536" height="1024" alt="lowlevel" src="https://github.com/user-attachments/assets/be209280-7c30-4f85-8328-faa95f17772b" />


The low-level architecture explains the internal processing flow of the system.

```text
EMAIL INGESTION & GATEWAY
        │
        ▼
Email Reader
        │
        ▼
Extract Email Data
        │
        ▼
Extract URLs and Attachments
        │
        ▼
Django Gateway
        │
        ▼
Validate and Forward Data
        │
        ▼
THREAT ANALYSIS & DECISION
        │
        ▼
IOC Extraction
        │
        ├── URLs
        ├── IP Addresses
        ├── Domains
        └── Suspicious Keywords
        │
        ▼
Threat Intelligence
        │
        ▼
Risk Calculation
        │
        ▼
Risk Classification
        │
        ▼
REPORTING & DELIVERY
        │
        ▼
Final JSON
        │
        ▼
Report Generator
        │
        ▼
HTML Security Report
        │
        ▼
Final Security Verdict
```

---

# Project Structure

```text
Gateway-Aggregation-Service/
│
├── attachments/
│
├── gateway/
│   ├── attachments/
│   ├── management/
│   ├── migrations/
│   ├── __pycache__/
│   │
│   ├── admin.py
│   ├── apps.py
│   ├── email_reader.py
│   ├── models.py
│   ├── processed_emails.json
│   ├── read_email.py
│   ├── risk_engine.py
│   ├── serializers.py
│   ├── tests.py
│   ├── urls.py
│   ├── views.py
│   └── __init__.py
│
├── Manasa_Risk_Engine/
│   │
│   └── risky/
│       ├── migrations/
│       ├── services/
│       ├── tests/
│       ├── __pycache__/
│       │
│       ├── admin.py
│       ├── apps.py
│       ├── models.py
│       ├── serializers.py
│       ├── urls.py
│       ├── views.py
│       └── __init__.py
│
├── Report_Generator/
│   │
│   ├── config_judgement_call/
│   │   ├── __pycache__/
│   │   ├── email_formatter.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   └── views.py
│   │
│   └── config/
│       ├── __pycache__/
│       ├── asgi.py
│       ├── settings.py
│       ├── urls.py
│       ├── wsgi.py
│       └── __init__.py
│
├── phishing_gateway/
│
├── .gitignore
├── db.sqlite3
├── manage.py
└── README.md
```

---

# 1. Email Gateway

The **Email Gateway** is responsible for receiving and processing incoming emails.

## Main Responsibilities

* Connect to Gmail using IMAP.
* Read incoming emails.
* Extract sender information.
* Extract receiver information.
* Extract email subject.
* Extract email body.
* Extract URLs.
* Download attachments.
* Build standardized email JSON.
* Validate email data.
* Prevent duplicate email processing.
* Forward the email data to the Risk Engine.

---

## Important Gateway Files

### `email_reader.py`

Responsible for reading and processing incoming emails.

Main functionality includes:

* Gmail connection.
* Email reading.
* Email parsing.
* Attachment downloading.
* URL extraction.

---

### `read_email.py`

Handles the email reading process.

---

### `serializers.py`

Validates and serializes email data before processing.

---

### `views.py`

Handles API requests related to the Gateway.

---

### `urls.py`

Defines the API routes for the Gateway module.

---

### `risk_engine.py`

Responsible for communicating with the Risk Engine.

The Gateway forwards the processed email payload to the Risk Engine for security analysis.

---

### `processed_emails.json`

Stores information about already processed emails.

This helps prevent duplicate email processing.

---

# 2. Risk Engine

The **Risk Engine** is responsible for analyzing the email and determining its security risk.

The Risk Engine receives validated email data from the Gateway.

---

## Risk Engine Processing Flow

```text
Incoming Email JSON
        ↓
Data Validation
        ↓
Email Content Processing
        ↓
IOC Extraction
        ↓
Threat Intelligence Analysis
        ↓
Risk Calculation
        ↓
Risk Classification
        ↓
Final Risk Analysis JSON
```

---

# Data Validation

The incoming request is validated using:

```text
RiskInputSerializer
```

The serializer validates important email information such as:

* Email ID
* Sender
* Receiver
* Subject
* Body
* URLs
* Attachments

After validation, the Risk Engine processes the validated data.

---

# IOC Extraction

The IOC Extractor analyzes the email content and extracts security indicators.

The system can identify:

* URLs
* IP Addresses
* Domains
* Suspicious Keywords

Example:

```text
https://example.com/security-verification

192.168.1.10

verify your account

urgent

login
```

---

# Suspicious Keyword Detection

The system checks the email content for suspicious keywords commonly used in phishing emails.

Examples include:

```text
urgent
immediately
verify your account
suspended
click here
password
login
confirm your account
bank account
otp
limited time
security alert
```

Detected suspicious keywords are included in the final security report.

---

# Threat Intelligence Analysis

The extracted IOCs are sent for threat intelligence analysis.

The analysis provides security statistics such as:

* Malicious detections.
* Suspicious detections.
* Harmless detections.
* Undetected results.

Example:

| IOC | Malicious | Suspicious | Harmless | Undetected |
| --- | --------: | ---------: | -------: | ---------: |
| URL |         2 |          1 |       45 |         20 |

The threat intelligence results are used by the Risk Engine to calculate the final security risk.

---

# Risk Calculation

The Risk Calculator calculates the final risk score based on multiple security indicators.

The calculation considers:

```text
AI Risk
+
IOC Count
+
Malicious Indicators
+
Suspicious Indicators
-
Harmless Indicators
```

The final score is normalized to a range of:

```text
0 – 100
```

The Risk Calculator also provides a score breakdown.

---

# Risk Classification

After calculating the final risk score, the Risk Classifier determines the security classification.

Example classifications include:

```text
SAFE
SUSPICIOUS
MALICIOUS
```

The final classification is included in the Risk Analysis response.

---

# TLP Classification

The system supports TLP information for IOC results.

The TLP value can be used to visually represent the severity or security classification of an IOC.

| IOC Classification | TLP       |
| ------------------ | --------- |
| Malicious          | 🔴 RED    |
| Suspicious         | 🟠 ORANGE |
| Harmless / Safe    | 🟢 GREEN  |

---

# Final Risk Engine JSON

The Risk Engine prepares a final structured JSON response containing:

```text
email_id

risk_analysis
    ├── risk_score
    ├── classification
    └── score_breakdown

threat_intelligence
    ├── total_iocs
    ├── malicious_count
    ├── suspicious_count
    ├── harmless_count
    ├── undetected_count
    └── ioc_results

attachments
```

---

# Example Risk Engine Response

```json
{
    "success": true,
    "message": "Risk analysis completed successfully.",
    "email_id": 168,
    "risk_analysis": {
        "risk_score": 54,
        "classification": "SUSPICIOUS"
    },
    "threat_intelligence": {
        "total_iocs": 4,
        "malicious_count": 2,
        "suspicious_count": 1,
        "harmless_count": 1,
        "undetected_count": 182,
        "ioc_results": []
    },
    "attachments": []
}
```

---

# 3. Report Generator

The **Report Generator** receives the final Risk Analysis JSON and generates the final security report.

---

## Main Responsibilities

* Receive the Risk Engine results.
* Validate the final JSON.
* Process Risk Analysis information.
* Process Threat Intelligence information.
* Process IOC results.
* Process attachments.
* Format the HTML security report.
* Display the final risk score.
* Display the final classification.
* Display IOC details.
* Display TLP information.
* Generate the final security report.

---

# Important Report Generator Files

## `email_formatter.py`

This file is responsible for formatting the security report.

It generates the HTML report containing:

* Email details.
* Risk summary.
* Threat Intelligence summary.
* Suspicious keywords.
* Attachments.
* IOC analysis.
* TLP information.
* Final security verdict.

---

## `views.py`

Handles API requests for receiving the final Risk Engine results.

---

## `urls.py`

Defines the API routes for the Report Generator.

---

## `models.py`

Contains database models used by the Report Generator.

---

# Security Report Structure

The generated security report contains the following sections.

---

## Email Details

The report displays:

```text
Email ID
```

Additional email details can be included based on the available data.

---

## Risk Summary

The Risk Summary displays:

* Risk Score.
* Final Classification.
* Risk Level.

Example:

```text
Risk Score: 54/100

Final Classification: SUSPICIOUS

Risk Level: MEDIUM
```

---

## Threat Intelligence Summary

The report displays:

| Metric             | Description                              |
| ------------------ | ---------------------------------------- |
| Total IOCs         | Total extracted Indicators of Compromise |
| Malicious IOCs     | Number of malicious detections           |
| Suspicious IOCs    | Number of suspicious detections          |
| Harmless IOCs      | Number of harmless detections            |
| Undetected Results | Number of undetected results             |

---

# Detected Suspicious Keywords

The report displays suspicious keywords detected in the email content.

Example:

```text
immediately

verify your account

suspended

login
```

---

# Attachments

The report displays attachments associated with the email.

| Filename | Content Type |
|---|---|
| document.pdf | application/pdf |
| image.png / image.jpg | image/png / image/jpeg |
| spreadsheet.xlsx | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| document.docx | application/vnd.openxmlformats-officedocument.wordprocessingml.document |

If there are no attachments, the report displays:

```text
No attachments found.
If there are no attachments, the report displays:

```text
No attachments found.
```

---

# IOC Analysis

The IOC Analysis table contains:

| # | Type | IOC Value | Malicious | Suspicious | Harmless | Undetected | Classification |
| - | ---- | --------- | --------: | ---------: | -------: | ---------: | -------------- |

Example classifications:

```text
MALICIOUS → RED

SUSPICIOUS → ORANGE

HARMLESS → GREEN
```

---

# Final Security Verdict

The final section of the report displays:

```text
Final Classification

Final Risk Score
```

Example:

```text
SUSPICIOUS

Final Risk Score: 54/100
```

---

<img width="188" height="362" alt="result_report" src="https://github.com/user-attachments/assets/ea18ee88-d723-4c6e-92cf-3e950f40465d" />


## Put Final Result Report Image Here

<!-- PUT FINAL RESULT REPORT IMAGE HERE -->

The final report provides a complete security analysis of the processed email.

It includes:

* Email Details
* Risk Summary
* Threat Intelligence Summary
* Detected Suspicious Keywords
* Attachments
* IOC Analysis
* IOC Classification
* TLP Classification
* Final Security Verdict

---

# Complete End-to-End Flow

```text
┌───────────────┐
│  Gmail Inbox  │
└───────┬───────┘
        │
        ▼
┌──────────────────────┐
│    Email Reader      │
│                      │
│ Read Email           │
│ Extract URLs         │
│ Download Attachments │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Django Gateway     │
│                      │
│ Validate Email JSON  │
│ Prepare Payload      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│     Risk Engine      │
│                      │
│ Validate Data        │
│ Extract IOCs         │
│ Threat Intelligence  │
│ Calculate Risk       │
│ Classification       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Final Analysis     │
│        JSON          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Report Generator   │
│                      │
│ Format HTML Report   │
│ IOC Analysis         │
│ TLP Classification   │
│ Final Verdict        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Final Security Report│
└──────────────────────┘
```

---

# Technology Stack

The project uses the following technologies:

* Python
* Django
* Django REST Framework
* REST APIs
* JSON
* SQLite
* Requests
* IMAP
* SMTP
* HTML

---

# Running the Project

## Activate the Virtual Environment

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Then activate the environment:

```powershell
& d:\OPTIMAS\PHISHY_EMAIL\myenv\Scripts\Activate.ps1
```

---

## Navigate to the Project Directory

```powershell
cd D:\OPTIMAS\PHISHY_EMAIL\Gateway-Aggregation-Service
```

---

## Run the Django Server

```powershell
python manage.py runserver
```

---

# Complete System Output

The system provides the following automated security workflow:

```text
Incoming Email
        ↓
Email Processing
        ↓
URL and Attachment Extraction
        ↓
Email Validation
        ↓
IOC Extraction
        ↓
Threat Intelligence Analysis
        ↓
Risk Calculation
        ↓
Risk Classification
        ↓
TLP Classification
        ↓
Final JSON
        ↓
Report Generation
        ↓
Final Security Verdict
```

---

# Result

The system automatically processes incoming emails and performs security analysis to identify potential phishing threats.

The final result provides:

* Risk Score
* Risk Classification
* IOC Count
* Malicious Detections
* Suspicious Detections
* Harmless Detections
* Undetected Results
* Suspicious Keywords
* Attachment Details
* IOC Analysis
* TLP Classification
* Final Security Verdict

This provides a complete automated workflow for phishing email detection, threat analysis, risk classification, and security report generation.
