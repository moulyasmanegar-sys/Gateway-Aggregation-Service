



# ============================================================
# CONFIGURATION
# ============================================================




import imaplib
import email
import json
import os
import re
import time
import uuid
import requests

from email.utils import parseaddr


# ============================================================
# CONFIGURATION
# ============================================================

EMAIL = "priyapal3157@gmail.com"
APP_PASSWORD = "wvua wugi gxnb btvf"

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

DJANGO_URL = "http://127.0.0.1:8000/api/emails/"

ATTACHMENT_DIR = "attachments"

CHECK_INTERVAL = 10


# Monitor both Inbox and Spam
FOLDERS = [
    "INBOX",
    "[Gmail]/Spam",
]


# File used to remember already processed emails
PROCESSED_EMAILS_FILE = "processed_emails.json"


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

if not EMAIL or not APP_PASSWORD:
    raise RuntimeError(
        "Set EMAIL and APP_PASSWORD before running email_reader.py."
    )


if APP_PASSWORD == "YOUR_GMAIL_APP_PASSWORD":
    raise RuntimeError(
        "Replace YOUR_GMAIL_APP_PASSWORD "
        "with your real Gmail App Password."
    )


# ============================================================
# CREATE ATTACHMENTS DIRECTORY
# ============================================================

os.makedirs(
    ATTACHMENT_DIR,
    exist_ok=True
)


# ============================================================
# LOAD PROCESSED EMAILS
# ============================================================

def load_processed_emails():

    if not os.path.exists(PROCESSED_EMAILS_FILE):
        return set()

    try:
        with open(
            PROCESSED_EMAILS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            return set(data)

    except Exception:
        return set()


# ============================================================
# SAVE PROCESSED EMAILS
# ============================================================

def save_processed_emails(processed_emails):

    with open(
        PROCESSED_EMAILS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            list(processed_emails),
            file,
            indent=4
        )


# ============================================================
# CREATE UNIQUE ATTACHMENT FILE PATH
# ============================================================

def get_unique_filepath(filename):

    safe_filename = os.path.basename(filename)

    filepath = os.path.join(
        ATTACHMENT_DIR,
        safe_filename
    )

    if os.path.exists(filepath):

        name, extension = os.path.splitext(
            safe_filename
        )

        unique_filename = (
            f"{name}_{uuid.uuid4().hex[:8]}"
            f"{extension}"
        )

        filepath = os.path.join(
            ATTACHMENT_DIR,
            unique_filename
        )

    return filepath


# ============================================================
# EXTRACT EMAIL BODY AND ATTACHMENTS
# ============================================================

def extract_email_content(msg):

    plain_body = ""
    html_body = ""
    attachments = []

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()

            content_disposition = str(
                part.get(
                    "Content-Disposition",
                    ""
                )
            ).lower()

            filename = part.get_filename()


            # ------------------------------------------------
            # SAVE ATTACHMENTS
            # ------------------------------------------------

            if filename:

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    filepath = get_unique_filepath(
                        filename
                    )

                    with open(
                        filepath,
                        "wb"
                    ) as file:

                        file.write(payload)


                    # IMPORTANT:
                    # Send absolute filepath to Risk Engine
                    attachments.append(
                        {
                            "filename": os.path.basename(
                                filepath
                            ),

                            "filepath": os.path.abspath(
                                filepath
                            ),

                            "content_type": content_type
                        }
                    )

                continue


            # ------------------------------------------------
            # PLAIN TEXT BODY
            # ------------------------------------------------

            if (
                content_type == "text/plain"
                and "attachment"
                not in content_disposition
            ):

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    plain_body = payload.decode(
                        errors="ignore"
                    )


            # ------------------------------------------------
            # HTML BODY
            # ------------------------------------------------

            elif (
                content_type == "text/html"
                and "attachment"
                not in content_disposition
            ):

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    html_body = payload.decode(
                        errors="ignore"
                    )


    else:

        payload = msg.get_payload(
            decode=True
        )

        if payload:

            plain_body = payload.decode(
                errors="ignore"
            )


    # Prefer plain text
    if plain_body.strip():
        body = plain_body
    else:
        body = html_body


    return body, attachments


# ============================================================
# EXTRACT URLS
# ============================================================

def extract_urls(text):

    url_pattern = (
        r'https?://[^\s<>"\']+'
        r'|www\.[^\s<>"\']+'
    )

    urls = re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if url not in cleaned_urls:

            cleaned_urls.append(
                url
            )

    return cleaned_urls


# ============================================================
# CONNECT TO GMAIL
# ============================================================

def connect_to_gmail():

    print("\nConnecting to Gmail...")

    mail = imaplib.IMAP4_SSL(
        IMAP_SERVER,
        IMAP_PORT
    )

    try:

        mail.login(
            EMAIL,
            APP_PASSWORD
        )

    except imaplib.IMAP4.error as exc:

        raise RuntimeError(
            "Gmail login failed. "
            "Check EMAIL and APP_PASSWORD."
        ) from exc


    print("✅ Gmail Login Successful!")

    return mail


# ============================================================
# CHECK GENERATED REPORT
# ============================================================

def is_generated_report(subject):

    subject = subject or ""

    subject = subject.strip().lower()

    report_subjects = [
        "security risk analysis",
        "security risk analysis report",
        "security analysis report",
    ]

    return any(
        subject.startswith(item)
        for item in report_subjects
    )


# ============================================================
# GET UNIQUE EMAIL IDENTIFIER
# ============================================================

def get_email_identifier(msg, email_id, folder):

    message_id = msg.get(
        "Message-ID",
        ""
    ).strip()

    if message_id:

        return f"{folder}:{message_id}"

    return (
        f"{folder}:imap:"
        f"{email_id.decode(errors='ignore')}"
    )


# ============================================================
# PROCESS ONE EMAIL
# ============================================================

def process_email(
    mail,
    email_id,
    folder,
    processed_emails
):

    # --------------------------------------------------------
    # FETCH EMAIL
    # --------------------------------------------------------

    status, msg_data = mail.fetch(
        email_id,
        "(RFC822)"
    )

    if status != "OK":

        print(
            "❌ Failed to fetch email:",
            email_id
        )

        return False


    raw_email = msg_data[0][1]

    msg = email.message_from_bytes(
        raw_email
    )


    # --------------------------------------------------------
    # GET EMAIL DETAILS
    # --------------------------------------------------------

    sender = parseaddr(
        msg.get("From", "")
    )[1]

    receiver = parseaddr(
        msg.get("To", "")
    )[1]

    subject = msg.get(
        "Subject",
        ""
    )


    # --------------------------------------------------------
    # CREATE UNIQUE IDENTIFIER
    # --------------------------------------------------------

    unique_id = get_email_identifier(
        msg,
        email_id,
        folder
    )


    # --------------------------------------------------------
    # SKIP ALREADY PROCESSED EMAILS
    # --------------------------------------------------------

    if unique_id in processed_emails:
        return False


    # --------------------------------------------------------
    # SKIP GENERATED SECURITY REPORTS
    # --------------------------------------------------------

    if is_generated_report(subject):

        print(
            f"\n⏭️ Skipping generated report "
            f"in {folder}"
        )

        print(
            f"Subject: {subject}"
        )

        processed_emails.add(
            unique_id
        )

        save_processed_emails(
            processed_emails
        )

        mail.store(
            email_id,
            "+FLAGS",
            "\\Seen"
        )

        return False


    # --------------------------------------------------------
    # DISPLAY NEW EMAIL
    # --------------------------------------------------------

    print("\n" + "=" * 70)

    print("📩 NEW EMAIL DETECTED")

    print("=" * 70)

    print(f"📁 Folder: {folder}")
    print(f"📧 From: {sender}")
    print(f"📨 To: {receiver}")
    print(f"📝 Subject: {subject}")


    # --------------------------------------------------------
    # EXTRACT BODY + ATTACHMENTS
    # --------------------------------------------------------

    body, attachments = extract_email_content(
        msg
    )


    # --------------------------------------------------------
    # EXTRACT URLS
    # --------------------------------------------------------

    urls = extract_urls(
        body
    )


    # --------------------------------------------------------
    # CREATE JSON
    # --------------------------------------------------------

    email_json = {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "source_folder": folder
    }


    # --------------------------------------------------------
    # PRINT DETAILS
    # --------------------------------------------------------

    print("\n📄 EMAIL BODY:")

    print("-" * 70)

    print(body)

    print("-" * 70)


    print("\n🔗 URLs:")

    if urls:

        for url in urls:
            print(f" - {url}")

    else:

        print("No URLs found.")


    print("\n📎 Attachments:")

    if attachments:

        for attachment in attachments:

            print(
                f" - {attachment['filename']}"
            )

            print(
                f"   Path: {attachment['filepath']}"
            )

    else:

        print("No attachments found.")


    # --------------------------------------------------------
    # SEND TO DJANGO
    # --------------------------------------------------------

    print(
        "\n🚀 Sending email to Django Risk Engine..."
    )

    try:

        response = requests.post(
            DJANGO_URL,
            json=email_json,
            timeout=30
        )


        print(
            f"📡 Django Response: "
            f"{response.status_code}"
        )


        try:

            response_data = response.json()

            print(
                json.dumps(
                    response_data,
                    indent=4
                )
            )

        except ValueError:

            print(
                response.text
            )


        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if 200 <= response.status_code < 300:

            print(
                "\n✅ Email successfully sent "
                "to Django."
            )

            print(
                "📊 Security report should now "
                "be generated."
            )


            processed_emails.add(
                unique_id
            )

            save_processed_emails(
                processed_emails
            )


            mail.store(
                email_id,
                "+FLAGS",
                "\\Seen"
            )

            return True


        # ----------------------------------------------------
        # FAILURE
        # ----------------------------------------------------

        else:

            print(
                "\n⚠️ Django returned an error."
            )

            print(
                "Email will NOT be added "
                "to processed list."
            )

            return False


    except requests.exceptions.ConnectionError:

        print(
            "\n❌ Could not connect to Django."
        )

        print(
            "Make sure Django server is running."
        )

        return False


    except requests.exceptions.Timeout:

        print(
            "\n❌ Django request timed out."
        )

        return False


    except Exception as exc:

        print(
            "\n❌ Error sending email to Django:"
        )

        print(
            str(exc)
        )

        return False


# ============================================================
# CHECK ONE GMAIL FOLDER
# ============================================================

def check_folder(
    mail,
    folder,
    processed_emails
):

    print(
        f"\n🔍 Checking folder: {folder}"
    )


    # --------------------------------------------------------
    # SELECT FOLDER
    # --------------------------------------------------------

    status, _ = mail.select(
        folder
    )

    if status != "OK":

        print(
            f"⚠️ Could not select folder: "
            f"{folder}"
        )

        return False


    # --------------------------------------------------------
    # SEARCH ALL EMAILS
    # --------------------------------------------------------

    status, messages = mail.search(
        None,
        "ALL"
    )

    if status != "OK":

        print(
            f"❌ Could not search folder: "
            f"{folder}"
        )

        return False


    email_ids = messages[0].split()


    if not email_ids:
        return False


    # Check latest 20 emails
    email_ids = email_ids[-20:]


    print(
        f"📬 Checking latest "
        f"{len(email_ids)} email(s) "
        f"in {folder}"
    )


    found_new_email = False


    for email_id in email_ids:

        processed = process_email(
            mail,
            email_id,
            folder,
            processed_emails
        )


        if processed:

            found_new_email = True


    return found_new_email


# ============================================================
# CONTINUOUS EMAIL MONITOR
# ============================================================

def monitor_emails():

    processed_emails = load_processed_emails()


    print(
        f"\n📚 Previously processed emails: "
        f"{len(processed_emails)}"
    )


    mail = connect_to_gmail()


    try:

        while True:

            try:

                found_new_email = False


                # ------------------------------------------------
                # CHECK BOTH INBOX AND SPAM
                # ------------------------------------------------

                for folder in FOLDERS:

                    result = check_folder(
                        mail,
                        folder,
                        processed_emails
                    )


                    if result:

                        found_new_email = True


                # ------------------------------------------------
                # STATUS
                # ------------------------------------------------

                if not found_new_email:

                    print(
                        "\n📭 No new unprocessed emails "
                        "found."
                    )


                # ------------------------------------------------
                # WAIT
                # ------------------------------------------------

                print(
                    f"\n⏳ Waiting "
                    f"{CHECK_INTERVAL} seconds..."
                )


                time.sleep(
                    CHECK_INTERVAL
                )


            # ----------------------------------------------------
            # GMAIL CONNECTION ERROR
            # ----------------------------------------------------

            except (
                imaplib.IMAP4.abort,
                imaplib.IMAP4.error
            ) as exc:

                print(
                    "\n⚠️ Gmail connection lost:"
                )

                print(
                    str(exc)
                )


                try:
                    mail.logout()

                except Exception:
                    pass


                print(
                    "\n🔄 Reconnecting to Gmail..."
                )


                time.sleep(5)


                mail = connect_to_gmail()


            # ----------------------------------------------------
            # STOP
            # ----------------------------------------------------

            except KeyboardInterrupt:

                print(
                    "\n🛑 Email monitoring stopped."
                )

                break


            # ----------------------------------------------------
            # OTHER ERROR
            # ----------------------------------------------------

            except Exception as exc:

                print(
                    "\n❌ Monitoring error:"
                )

                print(
                    str(exc)
                )


                time.sleep(
                    CHECK_INTERVAL
                )


    finally:

        try:

            mail.logout()

            print(
                "\n✅ Gmail Connection Closed."
            )

        except Exception:
            pass


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    print("=" * 70)

    print(
        "📧 AUTOMATED GMAIL EMAIL READER"
    )

    print("=" * 70)

    print(
        f"Monitoring Account: {EMAIL}"
    )

    print(
        f"Django API: {DJANGO_URL}"
    )

    print(
        "Folders: INBOX + SPAM"
    )

    print(
        f"Check Interval: "
        f"{CHECK_INTERVAL} seconds"
    )

    print("=" * 70)

    monitor_emails()

