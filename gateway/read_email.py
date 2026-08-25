import imaplib
import email
import os

EMAIL = ""
APP_PASSWORD = ""

if not EMAIL or not APP_PASSWORD:
	raise RuntimeError(
		"Set EMAIL_ADDRESS and GMAIL_APP_PASSWORD before running read_email.py."
	)

mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login(EMAIL, APP_PASSWORD)

mail.select("INBOX")

status, messages = mail.search(None, "ALL")

email_ids = messages[0].split()

