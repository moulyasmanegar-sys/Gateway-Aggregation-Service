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

RESULTS_API_URL = "http://127.0.0.1:8002/api/results/"


# ============================================================
# CLEAN EMAIL
# ============================================================

def clean_email(value):
    if not value:
        return ""

    value = str(value).strip()

    match = re.search(
        r"mailto:([^)]+)",
        value
    )

    if match:
        return match.group(1).strip()

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

    match = re.search(
        r"\]\((https?://[^)]+)\)",
        value
    )

    if match:
        return match.group(1).strip()

    match = re.search(
        r"https?://[^\s\]\)]+",
        value
    )

    if match:
        return match.group(0).strip()

    return value


# ============================================================
# GET IOC CLASSIFICATION
# ============================================================

def get_ioc_classification(result):
    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)

    if malicious > 0:
        return "Malicious"

    if suspicious > 0:
        return "Suspicious"

    return "Harmless"


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

        email_data = incoming_data.get("data", {})

        # ====================================================
        # FALLBACK TO TOP-LEVEL DATA
        # ====================================================

        if not email_data:
            email_data = {
                "id": incoming_data.get("email_id"),
                "sender": incoming_data.get("sender", ""),
                "receiver": incoming_data.get("receiver", ""),
                "subject": incoming_data.get("subject", ""),
                "body": incoming_data.get("body", ""),
                "urls": incoming_data.get("urls", []),
                "timestamp": incoming_data.get("timestamp"),
                "attachments": incoming_data.get("attachments", []),
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

        for attachment in top_level_attachments + nested_attachments:
            if attachment not in attachments:
                attachments.append(attachment)

        email_data["attachments"] = attachments

        # ====================================================
        # STEP 4: BUILD NORMALIZED DATA
        # ====================================================

        normalized_data = {
            "message": incoming_data.get("message", ""),
            "email_id": incoming_data.get("email_id"),
            "urls": incoming_data.get("urls", []),
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
            email_data.get("sender", "")
        )

        receiver = clean_email(
            email_data.get("receiver", "")
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

        print("\nEMAIL DETAILS:")
        print("Sender:", sender)
        print("Receiver:", receiver)
        print("Subject:", subject)
        print("Body:", body)
        print("Attachments:", validated_attachments)

        # ====================================================
        # STEP 8: EXTRACT IOCs
        # ====================================================

        ioc_data = IOCExtractor.extract(
            subject=subject,
            body=body,
            attachments=validated_attachments
        )

        iocs = ioc_data.get(
            "iocs",
            []
        )

        extracted_urls = ioc_data.get(
            "urls",
            []
        )

        ips = ioc_data.get(
            "ips",
            []
        )

        domains = ioc_data.get(
            "domains",
            []
        )

        sha256_hashes = ioc_data.get(
            "sha256_hashes",
            []
        )

        md5_hashes = ioc_data.get(
            "md5_hashes",
            []
        )

        suspicious_keywords = ioc_data.get(
            "suspicious_keywords",
            []
        )

        # IOCExtractor returns attachment FILE IOCs
        # using the "attachments" key

        attachment_iocs = ioc_data.get(
            "attachments",
            []
        )

        # ====================================================
        # STEP 9: ADD INCOMING URLS
        # ====================================================

        incoming_urls = validated_data.get(
            "urls",
            []
        )

        nested_urls = email_data.get(
            "urls",
            []
        )

        all_urls = []

        for url in extracted_urls:
            cleaned = clean_url(url)

            if cleaned and cleaned not in all_urls:
                all_urls.append(cleaned)

        for url in incoming_urls:
            cleaned = clean_url(url)

            if cleaned and cleaned not in all_urls:
                all_urls.append(cleaned)

        for url in nested_urls:
            cleaned = clean_url(url)

            if cleaned and cleaned not in all_urls:
                all_urls.append(cleaned)

        # ====================================================
        # STEP 10: BUILD FINAL IOC LIST
        # ====================================================

        final_iocs = []

        for ioc in iocs:
            if ioc not in final_iocs:
                final_iocs.append(ioc)

        for url in all_urls:
            url_ioc = {
                "type": "URL",
                "value": url
            }

            if url_ioc not in final_iocs:
                final_iocs.append(url_ioc)

        ioc_count = len(final_iocs)

        print("\n======================================")
        print("FINAL IOC ANALYSIS")
        print("======================================")
        print("Total IOCs:", ioc_count)
        print("IOCs:", final_iocs)
        print("Attachment IOCs:", attachment_iocs)
        print("======================================\n")

        # ====================================================
        # STEP 11: ANALYZE ALL IOCs
        # ====================================================

        ioc_results = []

        total_malicious = 0
        total_suspicious = 0
        total_harmless = 0
        total_undetected = 0

        if final_iocs:

            try:
                virus_total_service = VirusTotalService()

                for ioc in final_iocs:

                    ioc_type = ioc.get("type")
                    ioc_value = ioc.get("value")

                    # FILE IOC needs filepath
                    filepath = ioc.get("filepath")

                    print(
                        f"\nAnalyzing {ioc_type}: "
                        f"{ioc_value}"
                    )

                    result = virus_total_service.analyze_ioc(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        filepath=filepath,
                    )

                    ioc_classification = get_ioc_classification(
                        result
                    )

                    result["classification"] = (
                        ioc_classification
                    )

                    result["type"] = ioc_type
                    result["value"] = ioc_value

                    ioc_results.append(result)

                    if ioc_classification == "Malicious":
                        total_malicious += 1

                    elif ioc_classification == "Suspicious":
                        total_suspicious += 1

                    else:
                        total_harmless += 1

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
                        "iocs": final_iocs,
                    },
                    status=status.HTTP_502_BAD_GATEWAY,
                )

        # ====================================================
        # STEP 12: RISK CALCULATION
        # ====================================================

        calculation = RiskCalculator.calculate(
            ioc_count=ioc_count,
            malicious_count=total_malicious,
            suspicious_count=total_suspicious,
            harmless_count=total_harmless,
            suspicious_keyword_count=len(
                suspicious_keywords
            ),
        )

        risk_score = calculation.get(
            "risk_score",
            0
        )

        # ====================================================
        # STEP 13: OVERALL RISK CLASSIFICATION
        # ====================================================

        overall_classification = RiskClassifier.classify(
            risk_score
        )

        print("\nRISK RESULT:")
        print("Risk Score:", risk_score)
        print(
            "Classification:",
            overall_classification
        )

        # ====================================================
        # STEP 14: PREPARE RESULT FOR THAKSHI
        # ====================================================

        thakshi_payload = {
            "email_id": email_id,

            "risk_analysis": {
                "risk_score": risk_score,
                "classification": overall_classification,
                "risk_level": calculation.get(
                    "risk_level",
                    "LOW"
                ),
                "score_breakdown": calculation.get(
                    "score_breakdown",
                    {}
                ),
            },

            "threat_intelligence": {
                "total_iocs": ioc_count,
                "malicious_count": total_malicious,
                "suspicious_count": total_suspicious,
                "harmless_count": total_harmless,
                "undetected_count": total_undetected,
                "ioc_results": ioc_results,
            },

            "ioc_analysis": {
                "total_iocs": ioc_count,
                "iocs": final_iocs,
                "ips": ips,
                "domains": domains,
                "sha256_hashes": sha256_hashes,
                "md5_hashes": md5_hashes,
                "attachment_iocs": attachment_iocs,
                "suspicious_keywords": suspicious_keywords,
            },

            "attachments": validated_attachments,
        }

        print("\n==========================")
        print("THAKSHI PAYLOAD")
        print("==========================")
        print(thakshi_payload)
        print("==========================\n")

        # ====================================================
        # STEP 15: SEND RESULT TO THAKSHI
        # ====================================================

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

            if not thakshi_response.ok:
                print("\nTHAKSHI API RETURNED ERROR")

                print(
                    "STATUS:",
                    thakshi_response.status_code
                )

                print(
                    "RESPONSE:",
                    thakshi_response.text
                )

        except requests.RequestException as error:

            print(
                "\nFAILED TO SEND RESULT TO THAKSHI"
            )

            print(
                "ERROR:",
                str(error)
            )

        # ====================================================
        # STEP 16: BUILD FINAL RESPONSE
        # ====================================================

        response_data = {
            "success": True,

            "message": (
                "IOC risk analysis completed successfully."
            ),

            "email_id": email_id,

            "email_details": {
                "sender": sender,
                "receiver": receiver,
                "subject": subject,
            },

            "attachments": validated_attachments,

            "ioc_analysis": {
                "total_iocs": ioc_count,
                "iocs": final_iocs,
                "urls": all_urls,
                "ips": ips,
                "domains": domains,
                "sha256_hashes": sha256_hashes,
                "md5_hashes": md5_hashes,
                "attachment_iocs": attachment_iocs,
                "suspicious_keywords": suspicious_keywords,
            },

            "threat_intelligence": {
                "total_iocs": ioc_count,
                "malicious_count": total_malicious,
                "suspicious_count": total_suspicious,
                "harmless_count": total_harmless,
                "undetected_count": total_undetected,
                "ioc_results": ioc_results,
            },

            "risk_analysis": {
                "risk_score": risk_score,
                "classification": overall_classification,
                "risk_level": calculation.get(
                    "risk_level",
                    "LOW"
                ),
                "score_breakdown": calculation.get(
                    "score_breakdown",
                    {}
                ),
                "ioc_statistics": calculation.get(
                    "ioc_statistics",
                    {}
                ),
            },
        }

        # ====================================================
        # STEP 17: PRINT FINAL RESPONSE
        # ====================================================

        print("\n======================================")
        print("RISK ENGINE RESPONSE")
        print("======================================")
        print(response_data)
        print("======================================\n")

        # ====================================================
        # STEP 18: RETURN RESPONSE
        # ====================================================

        return Response(
            response_data,
            status=status.HTTP_200_OK
        )