import imaplib
import email
EMAIL = "goweris19@gmail.com"
APP_PASSWORD = ""

mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login(EMAIL, APP_PASSWORD)

mail.select("INBOX")

status, messages = mail.search(None, "ALL")

email_ids = messages[0].split()

