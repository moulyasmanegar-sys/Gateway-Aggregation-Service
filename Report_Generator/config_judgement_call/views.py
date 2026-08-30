import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.db import connection, transaction

from .email_formatter import format_risk_email


@csrf_exempt
def receive_results(request):

    # -----------------------------------------
    # Validate HTTP method
    # -----------------------------------------

    if request.method != "POST":

        return JsonResponse(
            {
                "status": "error",
                "message": "Only POST method is allowed"
            },
            status=405
        )

    # -----------------------------------------
    # Parse JSON
    # -----------------------------------------

    try:

        data = json.loads(request.body)

    except json.JSONDecodeError:

        return JsonResponse(
            {
                "status": "error",
                "message": "Invalid JSON"
            },
            status=400
        )

    # -----------------------------------------
    # Validate required top-level fields
    # -----------------------------------------

    required_fields = [
        "email_id",
        "risk_analysis",
        "threat_intelligence"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in data
    ]

    if missing_fields:

        return JsonResponse(
            {
                "status": "error",
                "message": "Missing required fields",
                "missing_fields": missing_fields
            },
            status=400
        )

    # -----------------------------------------
    # Extract risk analysis
    # -----------------------------------------

    risk_analysis = data["risk_analysis"]

    if not isinstance(risk_analysis, dict):

        return JsonResponse(
            {
                "status": "error",
                "message": "risk_analysis must be an object"
            },
            status=400
        )

    required_risk_fields = [
        "risk_score",
        "classification"
    ]

    missing_risk_fields = [
        field
        for field in required_risk_fields
        if field not in risk_analysis
    ]

    if missing_risk_fields:

        return JsonResponse(
            {
                "status": "error",
                "message": "Missing risk analysis fields",
                "missing_fields": missing_risk_fields
            },
            status=400
        )

    risk_score = risk_analysis["risk_score"]
    classification = risk_analysis["classification"]

    # -----------------------------------------
    # Extract threat intelligence
    # -----------------------------------------

    threat_intelligence = data["threat_intelligence"]

    if not isinstance(threat_intelligence, dict):

        return JsonResponse(
            {
                "status": "error",
                "message": "threat_intelligence must be an object"
            },
            status=400
        )

    # -----------------------------------------
    # Validate IOC fields
    # -----------------------------------------

    required_threat_fields = [
        "total_iocs",
        "malicious_count",
        "suspicious_count",
        "harmless_count",
        "undetected_count",
        "ioc_results"
    ]

    missing_threat_fields = [
        field
        for field in required_threat_fields
        if field not in threat_intelligence
    ]

    if missing_threat_fields:

        return JsonResponse(
            {
                "status": "error",
                "message": "Missing threat intelligence fields",
                "missing_fields": missing_threat_fields
            },
            status=400
        )

    # -----------------------------------------
    # Validate IOC results
    # -----------------------------------------

    ioc_results = threat_intelligence["ioc_results"]

    if not isinstance(ioc_results, list):

        return JsonResponse(
            {
                "status": "error",
                "message": "ioc_results must be a list"
            },
            status=400
        )

    # -----------------------------------------
    # Print received data
    # -----------------------------------------

    print("\n======================================")
    print("RECEIVED RISK ENGINE RESULT")
    print("======================================")

    print(
        json.dumps(
            data,
            indent=4
        )
    )

    print("======================================\n")

    # -----------------------------------------
    # Save data to MySQL
    # -----------------------------------------

    try:

        with transaction.atomic():

            with connection.cursor() as cursor:

                # ---------------------------------
                # Save main report
                # ---------------------------------

                cursor.execute(
                    """
                    INSERT INTO reports (
                        email_id,
                        risk_score,
                        classification,
                        total_iocs,
                        malicious_count,
                        suspicious_count,
                        harmless_count,
                        undetected_count
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        data["email_id"],
                        risk_score,
                        classification,
                        threat_intelligence["total_iocs"],
                        threat_intelligence["malicious_count"],
                        threat_intelligence["suspicious_count"],
                        threat_intelligence["harmless_count"],
                        threat_intelligence["undetected_count"]
                    ]
                )

                # ---------------------------------
                # Get newly created report ID
                # ---------------------------------

                report_id = cursor.lastrowid

                print(
                    f"Report saved successfully. "
                    f"Report ID: {report_id}"
                )

                # ---------------------------------
                # Save each IOC result
                # ---------------------------------

                for result in ioc_results:

                    cursor.execute(
                        """
                        INSERT INTO ioc_results (
                            report_id,
                            ioc_type,
                            ioc_value,
                            malicious,
                            suspicious,
                            harmless,
                            undetected,
                            classification,
                            tlp
                        )
                        VALUES (
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s
                        )
                        """,
                        [
                            report_id,
                            result.get("type", ""),
                            result.get("value", ""),
                            result.get("malicious", 0),
                            result.get("suspicious", 0),
                            result.get("harmless", 0),
                            result.get("undetected", 0),
                            result.get(
                                "classification",
                                ""
                            ),
                            result.get("tlp", "")
                        ]
                    )

        print("IOC results saved successfully.")

    except Exception as error:

        print(
            "Database error:",
            str(error)
        )

        return JsonResponse(
            {
                "status": "error",
                "message": "Failed to save report to database",
                "error": str(error)
            },
            status=500
        )

    # -----------------------------------------
    # Generate HTML email report
    # -----------------------------------------

    subject = (
        f"Security Risk Analysis - "
        f"{classification}"
    )

    html_message = format_risk_email(data)

    # -----------------------------------------
    # Send email report
    # -----------------------------------------

    try:

        email = EmailMultiAlternatives(
            subject=subject,
            body="Security Risk Analysis Report.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[
                "priyapal3157@gmail.com"
            ],
        )

        email.attach_alternative(
            html_message,
            "text/html"
        )

        email.send(
            fail_silently=False
        )

        print(
            "Email report sent successfully."
        )

    except Exception as error:

        print(
            "Email error:",
            str(error)
        )

        return JsonResponse(
            {
                "status": "error",
                "message": (
                    "Report saved to database, "
                    "but email could not be sent"
                ),
                "report_id": report_id,
                "error": str(error)
            },
            status=500
        )

    # -----------------------------------------
    # Final API response
    # -----------------------------------------

    return JsonResponse(
        {
            "status": "success",
            "message": (
                "Report saved and email "
                "sent successfully"
            ),
            "report_id": report_id
        },
        status=200
    )