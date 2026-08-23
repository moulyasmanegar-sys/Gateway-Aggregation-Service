import imaplib
import email
import json
import re
import requests
from email.utils import parseaddr

EMAIL = "goweris19@gmail.com"
APP_PASSWORD = ""

mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login(EMAIL, APP_PASSWORD)

print("Login Successful!")

mail.select("INBOX")

status, messages = mail.search(None, "ALL")

mail_ids = messages[0].split()

for email_id in mail_ids[-5:]:

	status, msg_data = mail.fetch(email_id, "(RFC822)")

	raw_email = msg_data[0][1]

	msg = email.message_from_bytes(raw_email)

	# Extract sender, receiver, subject
	sender = parseaddr(msg["From"])[1]
	receiver = parseaddr(msg["To"])[1]
	subject = msg["Subject"]

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
				body = part.get_payload(decode=True).decode(errors="ignore")
				break
	else:
		body = msg.get_payload(decode=True).decode(errors="ignore")

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

	# Print details
	print("--------------------------------")
	print("Subject:", subject)
	print("From:", sender)
	print("To:", receiver)
	print("\nBody:")
	print(body)

	print("\nJSON:")
	print(json.dumps(email_json, ensure_ascii=False))

	# Send to Django
	response = requests.post(
		"http://127.0.0.1:8000/api/emails/",
		json=email_json
	)

	print("\nResponse from Django:")
	print(response.json())
