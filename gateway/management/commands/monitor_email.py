import imaplib
import email
import os
import re
import time
import requests

from email.header import decode_header
from email.utils import parseaddr

from django.core.management.base import BaseCommand


# ============================================================
# GMAIL CONFIGURATION
# ============================================================
EMAIL = "priyapal3157@gmail.com"
APP_PASSWORD = "wvua wugi gxnb btvf"


# ============================================================
# GATEWAY CONFIGURATION
# ============================================================

GATEWAY_URL = "http://127.0.0.1:8000/api/emails/"

ATTACHMENT_DIR = "attachments"

CHECK_INTERVAL = 10


class Command(BaseCommand):

    help = "Continuously monitor Gmail and process new unread emails"

    def handle(self, *args, **options):

        os.makedirs(
            ATTACHMENT_DIR,
            exist_ok=True
        )

        self.stdout.write(
            self.style.SUCCESS(
                "Email automation started..."
            )
        )

        while True:

            try:

                self.check_emails()

            except Exception as error:

                self.stdout.write(
                    self.style.ERROR(
                        f"Email check failed: {error}"
                    )
                )

            time.sleep(CHECK_INTERVAL)

    # ========================================================
    # CHECK UNREAD EMAILS
    # ========================================================

    def check_emails(self):

        mail = None

        try:

            # Connect to Gmail
            mail = imaplib.IMAP4_SSL(
                "imap.gmail.com"
            )

            # Login
            mail.login(
                EMAIL,
                APP_PASSWORD
            )

            self.stdout.write(
                self.style.SUCCESS(
                    "Gmail connected successfully."
                )
            )

            # Select inbox
            mail.select("INBOX")

            # Search unread emails
            status, messages = mail.search(
                None,
                "UNSEEN"
            )

            if status != "OK":

                self.stdout.write(
                    self.style.ERROR(
                        "Failed to search emails."
                    )
                )

                return

            email_ids = messages[0].split()

            if not email_ids:

                self.stdout.write(
                    "No new emails."
                )

                return

            self.stdout.write(
                f"Found {len(email_ids)} new email(s)"
            )

            # Process each email
            for email_id in email_ids:

                self.process_email(
                    mail,
                    email_id
                )

        finally:

            if mail:

                try:
                    mail.logout()
                except Exception:
                    pass

    # ========================================================
    # PROCESS EMAIL
    # ========================================================

    def process_email(
        self,
        mail,
        email_id
    ):

        status, msg_data = mail.fetch(
            email_id,
            "(RFC822)"
        )

        if status != "OK":

            self.stdout.write(
                self.style.ERROR(
                    "Failed to fetch email."
                )
            )

            return

        raw_email = msg_data[0][1]

        msg = email.message_from_bytes(
            raw_email
        )

        # ====================================================
        # SENDER
        # ====================================================

        sender = parseaddr(
            msg.get("From", "")
        )[1]

        # ====================================================
        # RECEIVER
        # ====================================================

        receiver = parseaddr(
            msg.get("To", "")
        )[1]

        # ====================================================
        # SUBJECT
        # ====================================================

        subject = msg.get(
            "Subject",
            ""
        )

        decoded_subject = decode_header(
            subject
        )

        subject_parts = []

        for value, encoding in decoded_subject:

            if isinstance(value, bytes):

                subject_parts.append(
                    value.decode(
                        encoding or "utf-8",
                        errors="ignore"
                    )
                )

            else:

                subject_parts.append(
                    value
                )

        subject = "".join(
            subject_parts
        )

        # ====================================================
        # BODY + ATTACHMENTS
        # ====================================================

        body = ""

        attachments = []

        if msg.is_multipart():

            for part in msg.walk():

                content_type = (
                    part.get_content_type()
                )

                content_disposition = str(
                    part.get(
                        "Content-Disposition",
                        ""
                    )
                )

                # ------------------------------------------------
                # EMAIL BODY
                # ------------------------------------------------

                if (
                    content_type == "text/plain"
                    and "attachment"
                    not in content_disposition.lower()
                ):

                    payload = part.get_payload(
                        decode=True
                    )

                    if payload:

                        body += payload.decode(
                            errors="ignore"
                        )

                # ------------------------------------------------
                # ATTACHMENTS
                # ------------------------------------------------

                filename = part.get_filename()

                if filename:

                    filepath = os.path.join(
                        ATTACHMENT_DIR,
                        filename
                    )

                    payload = part.get_payload(
                        decode=True
                    )

                    if payload:

                        with open(
                            filepath,
                            "wb"
                        ) as file:

                            file.write(
                                payload
                            )

                    attachments.append(
                        {
                            "filename": filename,
                            "filepath": filepath,
                            "content_type": content_type,
                        }
                    )

        else:

            payload = msg.get_payload(
                decode=True
            )

            if payload:

                body = payload.decode(
                    errors="ignore"
                )

        # ====================================================
        # EXTRACT URLS
        # ====================================================

        urls = re.findall(
            r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
            body
        )

        # ====================================================
        # BUILD JSON
        # ====================================================

        email_json = {
            "sender": sender,
            "receiver": receiver,
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachments": attachments,
        }

        self.stdout.write(
            self.style.SUCCESS(
                f"Processing email: {subject}"
            )
        )

        self.stdout.write(
            f"Sender: {sender}"
        )

        self.stdout.write(
            f"URLs found: {urls}"
        )

        # ====================================================
        # SEND TO GATEWAY API
        # ====================================================

        try:

            response = requests.post(
                GATEWAY_URL,
                json=email_json,
                timeout=30
            )

            self.stdout.write(
                f"Gateway Status: "
                f"{response.status_code}"
            )

            self.stdout.write(
                f"Gateway Response: "
                f"{response.text}"
            )

            if response.ok:

                self.stdout.write(
                    self.style.SUCCESS(
                        "Email successfully sent to Gateway."
                    )
                )

            else:

                self.stdout.write(
                    self.style.ERROR(
                        "Gateway returned an error."
                    )
                )

        except requests.exceptions.ConnectionError:

            self.stdout.write(
                self.style.ERROR(
                    "Could not connect to Gateway. "
                    "Make sure Django server is running."
                )
            )

        except requests.RequestException as error:

            self.stdout.write(
                self.style.ERROR(
                    f"Gateway request failed: {error}"
                )
            )