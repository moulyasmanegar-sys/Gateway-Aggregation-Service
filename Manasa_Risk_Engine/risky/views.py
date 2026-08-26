import re

import requests

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import RiskInputSerializer
from .services.virustotal_service import VirusTotalService
from .services.risk_calculator import RiskCalculator
from .services.classifier import RiskClassifier
from .services.ioc_extractor import IOCExtractor


# ============================================================
# THAKSHI RESULTS API
# ============================================================

RESULTS_API_URL = (
    "https://vixen-deepen-gown.ngrok-free.dev/api/results/"
)


# ============================================================
# CLEAN EMAIL
# ============================================================

def clean_email(value):

    if not value:
        return ""

    value = str(value).strip()

    # Example:
    # [moulya@gmail.com](mailto:moulya@gmail.com)

    match = re.search(
        r"mailto:([^)]+)",
        value
    )

    if match:
        return match.group(1).strip()

    # Normal email

    match = re.search(
        r"[\w\.-]+@[\w\.-]+\.\w+",
        value
    )

    if match:
        return match.group(0).strip()

    return value


# ============================================================
# CLEAN URL
# ============================================================

def clean_url(value):

    if not value:
        return ""

    value = str(value).strip()

    # Example:
    # [https://example.com](https://example.com)

    match = re.search(
        r"\]\((https?://[^)]+)\)",
        value
    )

    if match:
        return match.group(1).strip()

    # Normal URL

    match = re.search(
        r"https?://[^\s\])]+",
        value
    )

    if match:
        return match.group(0).strip()

    return value


# ============================================================
# RISK ANALYSIS API
# ============================================================

class RiskAnalysisView(APIView):

    def post(self, request):

        print("\n======================================")
        print("INCOMING RISK ENGINE REQUEST")
        print("======================================")
        print(request.data)
        print("======================================\n")

        # ====================================================
        # STEP 1: GET REQUEST DATA
        # ====================================================

        incoming_data = request.data

        # ====================================================
        # STEP 2: HANDLE NESTED EMAIL DATA
        # ====================================================

        email_data = incoming_data.get(
            "data",
            {}
        )

        # ====================================================
        # FALLBACK TO TOP-LEVEL DATA
        # ====================================================

        if not email_data:

            email_data = {
                "id": incoming_data.get(
                    "email_id"
                ),

                "sender": incoming_data.get(
                    "sender",
                    ""
                ),

                "receiver": incoming_data.get(
                    "receiver",
                    ""
                ),

                "subject": incoming_data.get(
                    "subject",
                    ""
                ),

                "body": incoming_data.get(
                    "body",
                    ""
                ),

                "urls": incoming_data.get(
                    "urls",
                    []
                ),

                "timestamp": incoming_data.get(
                    "timestamp"
                ),

                "attachments": incoming_data.get(
                    "attachments",
                    []
                ),
            }

        # ====================================================
        # STEP 3: NORMALIZE ATTACHMENTS
        # ====================================================

        top_level_attachments = incoming_data.get(
            "attachments",
            []
        )

        nested_attachments = email_data.get(
            "attachments",
            []
        )

        attachments = []

        for attachment in (
            top_level_attachments + nested_attachments
        ):

            if attachment not in attachments:
                attachments.append(attachment)

        # Add normalized attachments to email data

        email_data["attachments"] = attachments

        # ====================================================
        # STEP 4: BUILD NORMALIZED DATA
        # ====================================================

        normalized_data = {

            "message": incoming_data.get(
                "message",
                ""
            ),

            "email_id": incoming_data.get(
                "email_id"
            ),

            "urls": incoming_data.get(
                "urls",
                []
            ),

            "attachments": attachments,

            "data": email_data,
        }

        print("NORMALIZED DATA:")
        print(normalized_data)

        # ====================================================
        # STEP 5: VALIDATE REQUEST
        # ====================================================

        serializer = RiskInputSerializer(
            data=normalized_data
        )

        serializer.is_valid(
            raise_exception=True
        )

        validated_data = serializer.validated_data

        # ====================================================
        # STEP 6: GET EMAIL ID
        # ====================================================

        email_id = validated_data.get(
            "email_id"
        )

        # ====================================================
        # STEP 7: GET EMAIL CONTENT
        # ====================================================

        email_data = validated_data.get(
            "data",
            {}
        )

        sender = clean_email(
            email_data.get(
                "sender",
                ""
            )
        )

        receiver = clean_email(
            email_data.get(
                "receiver",
                ""
            )
        )

        subject = email_data.get(
            "subject",
            ""
        )

        body = email_data.get(
            "body",
            ""
        )

        validated_attachments = email_data.get(
            "attachments",
            []
        )

        print("EMAIL DETAILS:")
        print("Sender:", sender)
        print("Receiver:", receiver)
        print("Subject:", subject)
        print("Body:", body)
        print("Attachments:", validated_attachments)

        # ====================================================
        # STEP 8: CLEAN TOP-LEVEL URLS
        # ====================================================

        incoming_urls = validated_data.get(
            "urls",
            []
        )

        cleaned_incoming_urls = []

        for url in incoming_urls:

            cleaned = clean_url(url)

            if cleaned:
                cleaned_incoming_urls.append(
                    cleaned
                )

        # ====================================================
        # STEP 9: CLEAN NESTED URLS
        # ====================================================

        nested_urls = email_data.get(
            "urls",
            []
        )

        cleaned_nested_urls = []

        for url in nested_urls:

            cleaned = clean_url(url)

            if cleaned:
                cleaned_nested_urls.append(
                    cleaned
                )

        # ====================================================
        # STEP 10: EXTRACT IOCs
        # ====================================================

        ioc_data = IOCExtractor.extract(
            subject=subject,
            body=body,
        )

        extracted_urls = ioc_data.get(
            "urls",
            []
        )

        domains = ioc_data.get(
            "domains",
            []
        )

        suspicious_keywords = ioc_data.get(
            "suspicious_keywords",
            []
        )

        ioc_count = ioc_data.get(
            "ioc_count",
            0
        )

        # ====================================================
        # STEP 11: CLEAN EXTRACTED URLS
        # ====================================================

        cleaned_extracted_urls = []

        for url in extracted_urls:

            cleaned = clean_url(url)

            if cleaned:
                cleaned_extracted_urls.append(
                    cleaned
                )

        # ====================================================
        # STEP 12: COMBINE ALL URL SOURCES
        # ====================================================

        urls = []

        # URLs extracted from email body

        for url in cleaned_extracted_urls:

            if url not in urls:
                urls.append(url)

        # URLs from top-level JSON

        for url in cleaned_incoming_urls:

            if url not in urls:
                urls.append(url)

        # URLs from data.urls

        for url in cleaned_nested_urls:

            if url not in urls:
                urls.append(url)

        print("FINAL URLS FOR THREAT INTELLIGENCE:")
        print(urls)

        # ====================================================
        # STEP 13: VIRUSTOTAL ANALYSIS
        # ====================================================

        url_results = []

        total_malicious = 0
        total_suspicious = 0
        total_harmless = 0
        total_undetected = 0

        if urls:

            try:

                virus_total_service = (
                    VirusTotalService()
                )

                for url in urls:

                    print(
                        "Analyzing URL with VirusTotal:",
                        url
                    )

                    result = (
                        virus_total_service.analyze_url(
                            url
                        )
                    )

                    url_results.append(
                        result
                    )

                    total_malicious += result.get(
                        "malicious",
                        0
                    )

                    total_suspicious += result.get(
                        "suspicious",
                        0
                    )

                    total_harmless += result.get(
                        "harmless",
                        0
                    )

                    total_undetected += result.get(
                        "undetected",
                        0
                    )

            except Exception as error:

                print(
                    "VIRUSTOTAL ERROR:",
                    str(error)
                )

                return Response(
                    {
                        "success": False,

                        "message": (
                            "Threat intelligence "
                            "analysis failed."
                        ),

                        "email_id": email_id,

                        "error": str(error),

                        "urls": urls,
                    },

                    status=status.HTTP_502_BAD_GATEWAY,
                )

        # ====================================================
        # STEP 14: RISK CALCULATION
        # ====================================================

        calculation = RiskCalculator.calculate(

            ai_risk="LOW",

            ioc_count=ioc_count,

            malicious_count=total_malicious,

            suspicious_count=total_suspicious,

            harmless_count=total_harmless,

            total_urls=len(urls),
        )

        risk_score = calculation[
            "risk_score"
        ]

        # ====================================================
        # STEP 15: RISK CLASSIFICATION
        # ====================================================

        classification = (
            RiskClassifier.classify(
                risk_score
            )
        )

        # ====================================================
        # STEP 16: PREPARE RESULT FOR THAKSHI
        # ====================================================
        #
        # IMPORTANT:
        #
        # Thakshi expects:
        #
        # "risk_analysis": {...}
        #
        # instead of:
        #
        # "risk_score": ...
        # "classification": ...
        #
        # ====================================================

        thakshi_payload = {

            "email_id": email_id,

            "risk_analysis": {

                "risk_score": risk_score,

                "classification": classification,

                "score_breakdown": (
                    calculation.get(
                        "score_breakdown",
                        {}
                    )
                ),
            },

            "threat_intelligence": {

                "total_urls": len(urls),

                "malicious_count": total_malicious,

                "suspicious_count": total_suspicious,

                "harmless_count": total_harmless,

                "undetected_count": total_undetected,

                "url_results": url_results,
            },

            "attachments": validated_attachments,
        }

        print("\n==========================")
        print("THAKSHI PAYLOAD")
        print("==========================")
        print(thakshi_payload)
        print("==========================\n")

        # ====================================================
        # STEP 17: SEND RESULT TO THAKSHI
        # ====================================================

        thakshi_response = None

        try:

            thakshi_response = requests.post(

                RESULTS_API_URL,

                json=thakshi_payload,

                headers={
                    "Content-Type": "application/json",

                    "ngrok-skip-browser-warning": "1",
                },

                timeout=30,
            )

            print(
                "THAKSHI STATUS:",
                thakshi_response.status_code
            )

            print(
                "THAKSHI RESPONSE:",
                thakshi_response.text
            )

            # =================================================
            # HANDLE THAKSHI ERROR
            # =================================================

            if not thakshi_response.ok:

                print("\n======================================")
                print("THAKSHI API RETURNED ERROR")
                print("======================================")

                print(
                    "STATUS:",
                    thakshi_response.status_code
                )

                print(
                    "RESPONSE:",
                    thakshi_response.text
                )

                print("======================================\n")

        except requests.RequestException as error:

            print("\n======================================")
            print("FAILED TO SEND RESULT TO THAKSHI")
            print("======================================")

            print(
                "ERROR:",
                str(error)
            )

            print("======================================\n")

        # ====================================================
        # STEP 18: BUILD FINAL RESPONSE
        # ====================================================

        response_data = {

            "success": True,

            "message": (
                "Risk analysis completed successfully."
            ),

            "email_id": email_id,

            "email_details": {

                "sender": sender,

                "receiver": receiver,

                "subject": subject,
            },

            "attachments": validated_attachments,

            "ioc_analysis": {

                "ioc_count": ioc_count,

                "extracted_urls": urls,

                "domains": domains,

                "suspicious_keywords": (
                    suspicious_keywords
                ),
            },

            "risk_analysis": {

                "risk_score": risk_score,

                "classification": classification,

                "score_breakdown": (
                    calculation.get(
                        "score_breakdown",
                        {}
                    )
                ),
            },

            "threat_intelligence": {

                "total_urls": len(urls),

                "malicious_count": total_malicious,

                "suspicious_count": total_suspicious,

                "harmless_count": total_harmless,

                "undetected_count": total_undetected,

                "url_results": url_results,
            },
        }

        # ====================================================
        # STEP 19: PRINT FINAL RESPONSE
        # ====================================================

        print("\n======================================")
        print("RISK ENGINE RESPONSE")
        print("======================================")
        print(response_data)
        print("======================================\n")

        # ====================================================
        # STEP 20: RETURN RESPONSE
        # ====================================================

        return Response(
            response_data,
            status=status.HTTP_200_OK
        )