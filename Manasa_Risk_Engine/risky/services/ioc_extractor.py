import re

from urllib.parse import urlparse


class IOCExtractor:

    # ==========================================
    # URL PATTERN
    # ==========================================

    URL_PATTERN = r'https?://[^\s<>"\']+'

    # ==========================================
    # IPv4 ADDRESS PATTERN
    # ==========================================

    IP_PATTERN = (
        r'\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
        r'(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b'
    )

    # ==========================================
    # SHA256 HASH PATTERN
    # ==========================================

    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'

    # ==========================================
    # MD5 HASH PATTERN
    # ==========================================

    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'

    # ==========================================
    # SUSPICIOUS KEYWORDS
    # ==========================================

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

    # ==========================================
    # EXTRACT IOCs
    # ==========================================

    @classmethod
    def extract(
        cls,
        subject="",
        body="",
        attachments=None
    ):

        # --------------------------------------
        # HANDLE EMPTY ATTACHMENTS
        # --------------------------------------

        if attachments is None:

            attachments = []

        # --------------------------------------
        # COMBINE SUBJECT AND BODY
        # --------------------------------------

        text = f"{subject} {body}"

        # ======================================
        # 1. EXTRACT URLs
        # ======================================

        urls = re.findall(

            cls.URL_PATTERN,

            text

        )

        urls = list(

            dict.fromkeys(urls)

        )

        # ======================================
        # 2. EXTRACT IP ADDRESSES
        # ======================================

        ips = re.findall(

            cls.IP_PATTERN,

            text

        )

        ips = list(

            dict.fromkeys(ips)

        )

        # ======================================
        # 3. EXTRACT DOMAINS FROM URLs
        # ======================================

        domains = []

        for url in urls:

            try:

                domain = urlparse(

                    url

                ).netloc

                if domain:

                    domain = domain.split(":")[0]

                    if domain not in domains:

                        domains.append(

                            domain

                        )

            except Exception:

                continue

        # ======================================
        # 4. EXTRACT SHA256 HASHES
        # ======================================

        sha256_hashes = re.findall(

            cls.SHA256_PATTERN,

            text

        )

        sha256_hashes = list(

            dict.fromkeys(

                sha256_hashes

            )

        )

        # ======================================
        # 5. EXTRACT MD5 HASHES
        # ======================================

        md5_hashes = re.findall(

            cls.MD5_PATTERN,

            text

        )

        md5_hashes = list(

            dict.fromkeys(

                md5_hashes

            )

        )

        # ======================================
        # 6. DETECT SUSPICIOUS KEYWORDS
        # ======================================

        found_keywords = []

        text_lower = text.lower()

        for keyword in cls.SUSPICIOUS_KEYWORDS:

            if keyword.lower() in text_lower:

                found_keywords.append(

                    keyword

                )

        # ======================================
        # 7. BUILD INDIVIDUAL IOC LIST
        # ======================================

        iocs = []

        # --------------------------------------
        # URL IOCs
        # --------------------------------------

        for url in urls:

            iocs.append(

                {

                    "type": "URL",

                    "value": url

                }

            )

        # --------------------------------------
        # IP IOCs
        # --------------------------------------

        for ip in ips:

            iocs.append(

                {

                    "type": "IP",

                    "value": ip

                }

            )

        # --------------------------------------
        # SHA256 IOCs
        # --------------------------------------

        for sha256_hash in sha256_hashes:

            iocs.append(

                {

                    "type": "SHA256",

                    "value": sha256_hash

                }

            )

        # --------------------------------------
        # MD5 IOCs
        # --------------------------------------

        for md5_hash in md5_hashes:

            iocs.append(

                {

                    "type": "MD5",

                    "value": md5_hash

                }

            )

        # ======================================
        # 8. ADD ATTACHMENTS AS FILE IOCs
        # ======================================

        attachment_iocs = []

        for attachment in attachments:

            # ----------------------------------
            # HANDLE DICTIONARY ATTACHMENT
            # ----------------------------------

            if isinstance(

                attachment,

                dict

            ):

                filename = attachment.get(

                    "filename",

                    ""

                )

                content_type = attachment.get(

                    "content_type",

                    ""

                )

                filepath = attachment.get(

                    "filepath",

                    ""

                )

            # ----------------------------------
            # HANDLE STRING ATTACHMENT
            # ----------------------------------

            else:

                filename = str(

                    attachment

                )

                content_type = ""

                filepath = ""

            # ----------------------------------
            # SKIP EMPTY ATTACHMENT
            # ----------------------------------

            if not filename:

                continue

            # ----------------------------------
            # CREATE FILE IOC
            # ----------------------------------

            file_ioc = {

                "type": "FILE",

                "value": filename,

                "filename": filename,

                "content_type": content_type,

                "filepath": filepath

            }

            attachment_iocs.append(

                file_ioc

            )

            iocs.append(

                file_ioc

            )

        # ======================================
        # 9. TOTAL IOC COUNT
        # ======================================

        ioc_count = len(

            iocs

        )

        # ======================================
        # RETURN RESULTS
        # ======================================

        return {

            "iocs": iocs,

            "urls": urls,

            "ips": ips,

            "domains": domains,

            "sha256_hashes": sha256_hashes,

            "md5_hashes": md5_hashes,

            "attachments": attachment_iocs,

            "suspicious_keywords": found_keywords,

            "ioc_count": ioc_count,

        }