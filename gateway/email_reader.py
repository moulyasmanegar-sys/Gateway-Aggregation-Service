import imaplib
import email
import json
import os
import re
import requests
from email.utils import parseaddr

# Gmail credentials must be provided through environment variables.
EMAIL = ""
APP_PASSWORD = ""

if not EMAIL or not APP_PASSWORD:
    raise RuntimeError(
        "Set EMAIL_ADDRESS and GMAIL_APP_PASSWORD before running email_reader.py."
    )

# Connect to Gmail
mail = imaplib.IMAP4_SSL("imap.gmail.com")
try:
    mail.login(EMAIL, APP_PASSWORD)
except imaplib.IMAP4.error as exc:
    raise RuntimeError(
        "Gmail rejected the login. Check that IMAP is enabled and that "
        "GMAIL_APP_PASSWORD is a current 16-character Google app password."
    ) from exc

print("✅ Login Successful!")

# Select Inbox
mail.select("INBOX")

# Get all emails
status, messages = mail.search(None, "ALL")
mail_ids = messages[0].split()

# Read last 5 emails
for email_id in mail_ids[-5:]:

    status, msg_data = mail.fetch(email_id, "(RFC822)")
    raw_email = msg_data[0][1]

    msg = email.message_from_bytes(raw_email)

    # Extract sender, receiver, subject
    sender = parseaddr(msg.get("From"))[1]
    receiver = parseaddr(msg.get("To"))[1]
    subject = msg.get("Subject", "")

    # Extract body
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if (
                content_type == "text/plain"
                and "attachment" not in content_disposition
            ):
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="ignore")
                break
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    # Extract URLs
    urls = re.findall(r'https?://\S+|www\.\S+', body)

    # Create JSON
    email_json = {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "body": body,
        "urls": urls
    }

    # Print Email Details
    print("\n--------------------------------")
    print("Subject :", subject)
    print("From    :", sender)
    print("To      :", receiver)
    print("\nBody:\n")
    print(body)

    print("\nJSON:")
    print(json.dumps(email_json, indent=4, ensure_ascii=False))

    # Send JSON to Django API
    try:
        response = requests.post(
            "http://127.0.0.1:8000/api/emails/",
            json=email_json,
            timeout=10
        )

        print("\nResponse from Django:")
        print(response.status_code)
        print(response.json())

    except requests.exceptions.ConnectionError:
        print("\n❌ Could not connect to Django.")
        print("Make sure 'python manage.py runserver' is running.")

    except Exception as e:
        print("\n❌ Error:", e)

# Logout
mail.logout()
print("\n✅ Gmail connection closed.")