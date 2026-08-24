import os
import smtplib

from email.message import EmailMessage
from dotenv import load_dotenv


# --------------------------------------------------
# Load environment variables
# --------------------------------------------------

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


# --------------------------------------------------
# Create email subject
# --------------------------------------------------

def create_subject(classification):

    classification = str(classification).upper()

    if classification == "SAFE":
        return "Security Analysis Result - Safe"

    elif classification == "SUSPICIOUS":
        return "Security Alert - Suspicious Content Detected"

    elif classification == "MALICIOUS":
        return "Security Alert - Malicious Content Detected"

    elif classification == "LOW":
        return "Security Analysis Result - Low Risk"

    elif classification == "MEDIUM":
        return "Security Alert - Medium Risk"

    elif classification == "HIGH":
        return "Security Alert - High Risk"

    else:
        return "Security Analysis Result"


# --------------------------------------------------
# Create recommendation
# --------------------------------------------------

def create_recommendation(classification):

    classification = str(classification).upper()

    if classification == "SAFE":

        return (
            "The analyzed content appears safe based on the "
            "available threat intelligence results."
        )

    elif classification in ["SUSPICIOUS", "MEDIUM"]:

        return (
            "Exercise caution when interacting with the "
            "analyzed content. Further investigation is recommended."
        )

    elif classification in ["MALICIOUS", "HIGH"]:

        return (
            "Do not interact with the detected malicious content. "
            "The security team should investigate this activity."
        )

    elif classification == "LOW":

        return (
            "No significant threat was identified. "
            "Continue to exercise normal security precautions."
        )

    else:

        return (
            "Please review the security analysis before interacting "
            "with the analyzed content."
        )


# --------------------------------------------------
# Create email body
# --------------------------------------------------

def create_email(report, recipient):

    email_id = report.get("email_id")
    risk_score = report.get("risk_score")
    classification = report.get("classification")

    threat_intelligence = report.get(
        "threat_intelligence",
        {}
    )

    total_urls = threat_intelligence.get(
        "total_urls",
        0
    )

    malicious_count = threat_intelligence.get(
        "malicious_count",
        0
    )

    suspicious_count = threat_intelligence.get(
        "suspicious_count",
        0
    )

    harmless_count = threat_intelligence.get(
        "harmless_count",
        0
    )

    undetected_count = threat_intelligence.get(
        "undetected_count",
        0
    )

    url_results = threat_intelligence.get(
        "url_results",
        []
    )

    subject = create_subject(classification)

    recommendation = create_recommendation(
        classification
    )


    # --------------------------------------------------
    # Build URL details
    # --------------------------------------------------

    url_details = ""

    for result in url_results:

        url = result.get("url", "Unknown")

        malicious = result.get(
            "malicious",
            0
        )

        suspicious = result.get(
            "suspicious",
            0
        )

        harmless = result.get(
            "harmless",
            0
        )

        undetected = result.get(
            "undetected",
            0
        )

        url_details += f"""
URL: {url}

Malicious: {malicious}
Suspicious: {suspicious}
Harmless: {harmless}
Undetected: {undetected}

"""


    # --------------------------------------------------
    # Create email body
    # --------------------------------------------------

    body = f"""
Hello,

The security analysis of your email has been completed.

Security Analysis Report
------------------------

Email ID: {email_id}

Risk Score: {risk_score}/100

Classification: {classification}

Threat Intelligence Summary
---------------------------

Total URLs: {total_urls}

Malicious: {malicious_count}

Suspicious: {suspicious_count}

Harmless: {harmless_count}

Undetected: {undetected_count}


URL Analysis
------------

{url_details}


Recommendation
--------------

{recommendation}


Regards,
Security Analysis System
"""


    return {
        "recipient": recipient,
        "subject": subject,
        "body": body
    }


# --------------------------------------------------
# Send email through Gmail SMTP
# --------------------------------------------------

def send_email(report, recipient):

    email = create_email(
        report,
        recipient
    )

    message = EmailMessage()

    message["From"] = SMTP_USER
    message["To"] = email["recipient"]
    message["Subject"] = email["subject"]

    message.set_content(
        email["body"]
    )


    try:

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT
        ) as server:

            # Upgrade connection to TLS
            server.starttls()

            # Authenticate with Gmail
            server.login(
                SMTP_USER,
                SMTP_PASSWORD
            )

            # Send email
            server.send_message(
                message
            )


        print("Email sent successfully!")

        return True


    except Exception as e:

        print(
            "Email sending failed:",
            e
        )

        return False


# --------------------------------------------------
# Test
# --------------------------------------------------

if __name__ == "__main__":

    test_report = {

        "email_id": 14,

        "risk_score": 13,

        "classification": "SAFE",

        "threat_intelligence": {

            "total_urls": 1,

            "malicious_count": 0,

            "suspicious_count": 0,

            "harmless_count": 58,

            "undetected_count": 34,

            "url_results": [

                {
                    "url": "https://www.techslash.com/fi",

                    "malicious": 0,

                    "suspicious": 0,

                    "harmless": 58,

                    "undetected": 34
                }

            ]
        }
    }


    # For testing only
    test_recipient = "employee@example.com"


    email = create_email(
        test_report,
        test_recipient
    )


    print("\nEMAIL PREVIEW")
    print("-------------")

    print(
        "To:",
        email["recipient"]
    )

    print(
        "Subject:",
        email["subject"]
    )

    print("\nBody:")

    print(
        email["body"]
    )