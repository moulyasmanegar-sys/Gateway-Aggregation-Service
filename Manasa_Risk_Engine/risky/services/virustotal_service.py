import time
import hashlib
import os
import requests

from django.conf import settings


class VirusTotalService:

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):

        self.api_key = settings.VIRUSTOTAL_API_KEY

        if not self.api_key:
            raise ValueError(
                "VIRUSTOTAL_API_KEY is not configured."
            )

        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    # ====================================================
    # CALCULATE FILE SHA256
    # ====================================================

    def calculate_file_hash(self, filepath):

        if not filepath:
            raise ValueError(
                "File path is missing."
            )

        if not os.path.exists(filepath):
            raise FileNotFoundError(
                f"Attachment file not found: {filepath}"
            )

        sha256 = hashlib.sha256()

        with open(filepath, "rb") as file:

            while True:

                chunk = file.read(8192)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    # ====================================================
    # ANALYZE URL
    # ====================================================

    def analyze_url(self, url):

        try:

            submit_response = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                data={
                    "url": url
                },
                timeout=10,
            )

            submit_response.raise_for_status()

            response_data = submit_response.json()

            analysis_id = response_data["data"]["id"]

        except requests.exceptions.Timeout:

            raise Exception(
                f"VirusTotal request timed out "
                f"while submitting URL: {url}"
            )

        except requests.exceptions.RequestException as error:

            raise Exception(
                f"VirusTotal URL submission failed: {error}"
            )

        except (KeyError, TypeError, ValueError):

            raise Exception(
                "VirusTotal returned an invalid "
                "URL analysis response."
            )

        return self._wait_for_analysis(
            analysis_id=analysis_id,
            ioc_type="URL",
            ioc_value=url,
        )

    # ====================================================
    # ANALYZE IP ADDRESS
    # ====================================================

    def analyze_ip(self, ip):

        try:

            response = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=10,
            )

            if response.status_code == 404:

                print(
                    f"VirusTotal has no data for IP: {ip}"
                )

                return self._build_unknown_result(
                    ioc_type="IP",
                    ioc_value=ip,
                )

            response.raise_for_status()

            data = response.json()

            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return self._build_result(
                ioc_type="IP",
                ioc_value=ip,
                stats=stats,
            )

        except requests.exceptions.Timeout:

            raise Exception(
                f"VirusTotal request timed out "
                f"for IP: {ip}"
            )

        except requests.exceptions.RequestException as error:

            raise Exception(
                f"VirusTotal IP analysis failed: {error}"
            )

    # ====================================================
    # ANALYZE DOMAIN
    # ====================================================

    def analyze_domain(self, domain):

        try:

            response = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers,
                timeout=10,
            )

            if response.status_code == 404:

                print(
                    f"VirusTotal has no data for domain: "
                    f"{domain}"
                )

                return self._build_unknown_result(
                    ioc_type="DOMAIN",
                    ioc_value=domain,
                )

            response.raise_for_status()

            data = response.json()

            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return self._build_result(
                ioc_type="DOMAIN",
                ioc_value=domain,
                stats=stats,
            )

        except requests.exceptions.Timeout:

            raise Exception(
                f"VirusTotal request timed out "
                f"for domain: {domain}"
            )

        except requests.exceptions.RequestException as error:

            raise Exception(
                f"VirusTotal domain analysis failed: {error}"
            )

    # ====================================================
    # ANALYZE FILE HASH
    # ====================================================

    def analyze_file_hash(self, file_hash):

        try:

            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=10,
            )

            # --------------------------------------------
            # IMPORTANT:
            # 404 means VirusTotal does not have this file
            # hash in its database.
            # This should NOT crash the Risk Engine.
            # --------------------------------------------

            if response.status_code == 404:

                print(
                    "\nVirusTotal file hash not found."
                )

                print(
                    f"SHA256: {file_hash}"
                )

                print(
                    "Treating file as unknown/undetected."
                )

                return self._build_unknown_result(
                    ioc_type="FILE",
                    ioc_value=file_hash,
                )

            response.raise_for_status()

            data = response.json()

            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return self._build_result(
                ioc_type="FILE",
                ioc_value=file_hash,
                stats=stats,
            )

        except requests.exceptions.Timeout:

            raise Exception(
                f"VirusTotal request timed out "
                f"for file hash: {file_hash}"
            )

        except requests.exceptions.RequestException as error:

            raise Exception(
                f"VirusTotal file hash analysis failed: {error}"
            )

    # ====================================================
    # ANALYZE FILE ATTACHMENT
    # ====================================================

    def analyze_file(self, filepath, filename=""):

        file_hash = self.calculate_file_hash(
            filepath
        )

        print(
            f"\nFile SHA256 for {filename}: "
            f"{file_hash}"
        )

        result = self.analyze_file_hash(
            file_hash
        )

        result["type"] = "FILE"

        result["value"] = (
            filename or file_hash
        )

        result["sha256"] = file_hash

        result["filename"] = filename

        result["filepath"] = filepath

        return result

    # ====================================================
    # WAIT FOR URL ANALYSIS
    # ====================================================

    def _wait_for_analysis(
        self,
        analysis_id,
        ioc_type,
        ioc_value,
    ):

        max_attempts = 5

        for attempt in range(max_attempts):

            try:

                response = requests.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=10,
                )

                response.raise_for_status()

                data = response.json()

            except requests.exceptions.Timeout:

                raise Exception(
                    f"VirusTotal analysis timed out "
                    f"for {ioc_type}: {ioc_value}"
                )

            except requests.exceptions.RequestException as error:

                raise Exception(
                    f"VirusTotal analysis failed: {error}"
                )

            attributes = (
                data
                .get("data", {})
                .get("attributes", {})
            )

            analysis_status = attributes.get(
                "status"
            )

            if analysis_status == "completed":

                stats = attributes.get(
                    "stats",
                    {}
                )

                return self._build_result(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    stats=stats,
                )

            if analysis_status == "failed":

                raise Exception(
                    f"VirusTotal analysis failed "
                    f"for {ioc_type}: {ioc_value}"
                )

            if attempt < max_attempts - 1:

                time.sleep(2)

        return self._build_unknown_result(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )

    # ====================================================
    # BUILD STANDARD RESULT
    # ====================================================

    def _build_result(
        self,
        ioc_type,
        ioc_value,
        stats,
    ):

        return {
            "type": ioc_type,
            "value": ioc_value,
            "malicious": stats.get(
                "malicious",
                0
            ),
            "suspicious": stats.get(
                "suspicious",
                0
            ),
            "harmless": stats.get(
                "harmless",
                0
            ),
            "undetected": stats.get(
                "undetected",
                0
            ),
        }

    # ====================================================
    # BUILD UNKNOWN RESULT
    # ====================================================

    def _build_unknown_result(
        self,
        ioc_type,
        ioc_value,
    ):

        return {
            "type": ioc_type,
            "value": ioc_value,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 1,
            "status": "unknown",
            "message": (
                "VirusTotal has no existing data "
                "for this IOC."
            ),
        }

    # ====================================================
    # ANALYZE ANY IOC
    # ====================================================

    def analyze_ioc(
        self,
        ioc_type,
        ioc_value,
        filepath=None,
    ):

        ioc_type = ioc_type.upper()

        if ioc_type == "URL":

            return self.analyze_url(
                ioc_value
            )

        if ioc_type == "IP":

            return self.analyze_ip(
                ioc_value
            )

        if ioc_type == "DOMAIN":

            return self.analyze_domain(
                ioc_value
            )

        if ioc_type in [
            "MD5",
            "SHA256",
            "FILE_HASH",
        ]:

            return self.analyze_file_hash(
                ioc_value
            )

        if ioc_type == "FILE":

            return self.analyze_file(
                filepath=filepath,
                filename=ioc_value,
            )

        raise ValueError(
            f"Unsupported IOC type: {ioc_type}"
        )