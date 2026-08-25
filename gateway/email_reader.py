import imaplib
import email
import json
import os
import re
import requests
from email.utils import parseaddr

# ==============================
# Gmail Credentials
# ==============================
EMAIL = "goweris19@gmail.com"
APP_PASSWORD = "moda lbnj ocjf jxmg"      # Enter your Gmail App Password

if not EMAIL or not APP_PASSWORD:
    raise RuntimeError(
        "Set EMAIL and APP_PASSWORD before running email_reader.py."
    )

# ==============================
# Create Attachments Folder
# ==============================
ATTACHMENT_DIR = "attachments"
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

# ==============================
# Connect to Gmail
# ==============================
mail = imaplib.IMAP4_SSL("imap.gmail.com")

try:
    mail.login(EMAIL, APP_PASSWORD)
except imaplib.IMAP4.error as exc:
    raise RuntimeError(
        "Gmail rejected the login. Check your App Password."
    ) from exc

print("✅ Login Successful!")

# ==============================
# Select Inbox
# ==============================
mail.select("INBOX")

status, messages = mail.search(None, "ALL")
mail_ids = messages[0].split()

# ==============================
# Read Last 5 Emails
# ==============================
for email_id in mail_ids[-5:]:

    status, msg_data = mail.fetch(email_id, "(RFC822)")
    raw_email = msg_data[0][1]

    msg = email.message_from_bytes(raw_email)

    sender = parseaddr(msg.get("From"))[1]
    receiver = parseaddr(msg.get("To"))[1]
    subject = msg.get("Subject", "")

    body = ""
    attachments = []

    # ==========================
    # Read Email
    # ==========================
    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # -----------------------
            # Email Body
            # -----------------------
            if (
                content_type == "text/plain"
                and "attachment" not in content_disposition
            ):

                payload = part.get_payload(decode=True)

                if payload:
                    body = payload.decode(errors="ignore")

            # -----------------------
            # Attachments
            # -----------------------
            filename = part.get_filename()

            if filename:

                filepath = os.path.join(
                    ATTACHMENT_DIR,
                    filename
                )

                with open(filepath, "wb") as f:
                    f.write(part.get_payload(decode=True))

                attachments.append({
                    "filename": filename,
                    "filepath": filepath,
                    "content_type": content_type
                })

    else:

        payload = msg.get_payload(decode=True)

        if payload:
            body = payload.decode(errors="ignore")

    # ==========================
    # Extract URLs
    # ==========================
    urls = re.findall(r'https?://\S+|www\.\S+', body)

    # ==========================
    # JSON
    # ==========================
    email_json = {

        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachments": attachments

    }

    # ==========================
    # Print Details
    # ==========================
    print("\n========================================")
    print("Subject :", subject)
    print("From    :", sender)
    print("To      :", receiver)

    print("\nBody:\n")
    print(body)

    print("\nURLs:")
    print(urls)

    print("\nAttachments:")

    if attachments:
        for file in attachments:
            print("📎", file["filename"])
    else:
        print("No Attachments")

    print("\nJSON:\n")
    print(json.dumps(email_json, indent=4, ensure_ascii=False))

    # ==========================
    # Send to Django
    # ==========================
    try:

        response = requests.post(
            "http://127.0.0.1:8000/api/emails/",
            json=email_json,
            timeout=10
        )

        print("\nResponse From Django")
        print(response.status_code)
        print(response.json())

    except requests.exceptions.ConnectionError:

        print("\n❌ Could not connect to Django.")
        print("Run: python manage.py runserver")

    except Exception as e:

        print("\n❌ Error:", e)

# ==============================
# Logout
# ==============================
mail.logout()

print("\n✅ Gmail Connection Closed.")