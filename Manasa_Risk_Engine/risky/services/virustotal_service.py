import time
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

    def analyze_url(self, url):

        # ====================================================
        # STEP 1: SUBMIT URL TO VIRUSTOTAL
        # ====================================================

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

        except requests.exceptions.Timeout:

            raise Exception(
                f"VirusTotal request timed out while "
                f"submitting URL: {url}"
            )

        except requests.exceptions.RequestException as error:

            raise Exception(
                f"VirusTotal URL submission failed: {error}"
            )

        # ====================================================
        # STEP 2: READ VIRUSTOTAL RESPONSE
        # ====================================================

        try:

            response_data = submit_response.json()

        except ValueError:

            raise Exception(
                "VirusTotal returned an invalid JSON response."
            )

        # ====================================================
        # STEP 3: GET ANALYSIS ID
        # ====================================================

        try:

            analysis_id = (
                response_data["data"]["id"]
            )

        except (KeyError, TypeError):

            raise Exception(
                "VirusTotal response did not contain "
                "a valid analysis ID."
            )

        # ====================================================
        # STEP 4: CHECK ANALYSIS STATUS
        # ====================================================

        max_attempts = 5

        for attempt in range(max_attempts):

            try:

                analysis_response = requests.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=10,
                )

                analysis_response.raise_for_status()

            except requests.exceptions.Timeout:

                raise Exception(
                    f"VirusTotal analysis request timed out "
                    f"for URL: {url}"
                )

            except requests.exceptions.RequestException as error:

                raise Exception(
                    f"VirusTotal analysis request failed: {error}"
                )

            # =================================================
            # STEP 5: PARSE ANALYSIS RESPONSE
            # =================================================

            try:

                analysis_data = (
                    analysis_response.json()
                )

            except ValueError:

                raise Exception(
                    "VirusTotal returned an invalid "
                    "analysis response."
                )

            # =================================================
            # STEP 6: GET ATTRIBUTES
            # =================================================

            attributes = (
                analysis_data
                .get("data", {})
                .get("attributes", {})
            )

            analysis_status = (
                attributes.get("status")
            )

            # =================================================
            # STEP 7: ANALYSIS COMPLETED
            # =================================================

            if analysis_status == "completed":

                stats = attributes.get(
                    "stats",
                    {}
                )

                return {
                    "url": url,

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

            # =================================================
            # STEP 8: ANALYSIS FAILED
            # =================================================

            if analysis_status == "failed":

                raise Exception(
                    f"VirusTotal analysis failed "
                    f"for URL: {url}"
                )

            # =================================================
            # STEP 9: WAIT BEFORE CHECKING AGAIN
            # =================================================

            if attempt < max_attempts - 1:

                time.sleep(2)

        # ====================================================
        # STEP 10: ANALYSIS TIMEOUT
        # ====================================================

        return {
             "url": url,
             "malicious": 0,
             "suspicious": 0,
              "harmless": 0,
            "undetected": 1,
        }