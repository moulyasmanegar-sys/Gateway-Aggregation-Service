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
        received_data = json.loads(request.body)

    except json.JSONDecodeError:
        return JsonResponse(
            {
                "status": "error",
                "message": "Invalid JSON"
            },
            status=400
        )

    # -----------------------------------------
    # Validate required fields
    # -----------------------------------------

    required_fields = [
        "email_id",
        "risk_analysis",
        "threat_intelligence"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in received_data
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
    # Validate risk analysis
    # -----------------------------------------

    risk_analysis = received_data["risk_analysis"]

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

    # -----------------------------------------
    # Extract risk analysis values
    # -----------------------------------------

    risk_score = risk_analysis["risk_score"]
    classification = risk_analysis["classification"]

    # -----------------------------------------
    # Validate threat intelligence
    # -----------------------------------------

    threat_intelligence = received_data["threat_intelligence"]

    if not isinstance(threat_intelligence, dict):
        return JsonResponse(
            {
                "status": "error",
                "message": "threat_intelligence must be an object"
            },
            status=400
        )

    required_threat_fields = [
        "total_urls",
        "malicious_count",
        "suspicious_count",
        "harmless_count",
        "undetected_count",
        "url_results"
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
    # Validate URL results
    # -----------------------------------------

    url_results = threat_intelligence["url_results"]

    if not isinstance(url_results, list):
        return JsonResponse(
            {
                "status": "error",
                "message": "url_results must be a list"
            },
            status=400
        )

    # -----------------------------------------
    # Create only required JSON data
    # -----------------------------------------

    data = {
        "email_id": received_data["email_id"],

        "risk_analysis": {
            "risk_score": risk_analysis["risk_score"],
            "classification": risk_analysis["classification"]
        },

        "threat_intelligence": {
            "total_urls": threat_intelligence["total_urls"],
            "malicious_count": threat_intelligence["malicious_count"],
            "suspicious_count": threat_intelligence["suspicious_count"],
            "harmless_count": threat_intelligence["harmless_count"],
            "undetected_count": threat_intelligence["undetected_count"],
            "url_results": url_results
        }
    }

    # -----------------------------------------
    # Print only required data
    # -----------------------------------------

    print("Received required data:")
    print(json.dumps(data, indent=4))

    # -----------------------------------------
    # Save data to MySQL
    # -----------------------------------------

    try:

        with transaction.atomic():

            with connection.cursor() as cursor:

                # Save main report
                cursor.execute(
                    """
                    INSERT INTO reports (
                        email_id,
                        risk_score,
                        classification,
                        total_urls,
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
                        threat_intelligence["total_urls"],
                        threat_intelligence["malicious_count"],
                        threat_intelligence["suspicious_count"],
                        threat_intelligence["harmless_count"],
                        threat_intelligence["undetected_count"]
                    ]
                )

                # Get newly created report ID
                report_id = cursor.lastrowid

                print(
                    f"Report saved successfully. Report ID: {report_id}"
                )

                # Save each URL result
                for result in url_results:

                    cursor.execute(
                        """
                        INSERT INTO url_results (
                            report_id,
                            url,
                            malicious,
                            suspicious,
                            harmless,
                            undetected
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        [
                            report_id,
                            result.get("url", ""),
                            result.get("malicious", 0),
                            result.get("suspicious", 0),
                            result.get("harmless", 0),
                            result.get("undetected", 0)
                        ]
                    )

        print("URL results saved successfully.")

    except Exception as e:

        print("Database error:", str(e))

        return JsonResponse(
            {
                "status": "error",
                "message": "Failed to save report to database",
                "error": str(e)
            },
            status=500
        )

    # -----------------------------------------
    # Generate HTML email report
    # -----------------------------------------

    subject = f"Security Risk Analysis - {classification}"

    html_message = format_risk_email(data)

    # -----------------------------------------
    # Send email
    # -----------------------------------------

    try:

        email = EmailMultiAlternatives(
            subject=subject,
            body="Security Risk Analysis Report.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=["goweris19@gmail.com"],
        )

        email.attach_alternative(
            html_message,
            "text/html"
        )

        email.send(fail_silently=False)

        print("Email report sent successfully.")

    except Exception as e:

        print("Email error:", str(e))

        return JsonResponse(
            {
                "status": "error",
                "message": "Report saved to database, but email could not be sent",
                "report_id": report_id,
                "error": str(e)
            },
            status=500
        )

    # -----------------------------------------
    # API response
    # -----------------------------------------

    return JsonResponse(
        {
            "status": "success",
            "message": "Report saved and email sent successfully",
            "report_id": report_id,
            "received_data": data
        },
        status=200
    )