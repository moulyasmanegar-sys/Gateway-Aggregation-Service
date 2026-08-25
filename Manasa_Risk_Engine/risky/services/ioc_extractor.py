import re
from urllib.parse import urlparse


class IOCExtractor:

    URL_PATTERN = r'https?://[^\s<>"\']+'

    SUSPICIOUS_KEYWORDS = [
        "urgent",
        "immediately",
        "verify your account",
        "suspended",
        "click here",
        "password",
        "login",
        "confirm your account",
        "bank account",
        "otp",
        "limited time",
        "security alert",
    ]

    @classmethod
    def extract(cls, subject="", body=""):
        text = f"{subject} {body}"

        # Extract URLs
        urls = re.findall(cls.URL_PATTERN, text)

        # Remove duplicates
        urls = list(dict.fromkeys(urls))

        # Extract domains
        domains = []

        for url in urls:
            try:
                domain = urlparse(url).netloc

                if domain and domain not in domains:
                    domains.append(domain)

            except Exception:
                continue

        # Detect suspicious keywords
        found_keywords = []

        text_lower = text.lower()

        for keyword in cls.SUSPICIOUS_KEYWORDS:
            if keyword.lower() in text_lower:
                found_keywords.append(keyword)

        # IOC count
        ioc_count = len(urls) + len(found_keywords)

        return {
            "urls": urls,
            "domains": domains,
            "suspicious_keywords": found_keywords,
            "ioc_count": ioc_count,
        }