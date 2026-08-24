from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json


@csrf_exempt
def receive_results(request):

    if request.method != "POST":
        return JsonResponse(
            {
                "status": "error",
                "message": "Only POST method is allowed"
            },
            status=405
        )

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
    # Validate required fields
    # -----------------------------------------

    required_fields = [
        "email_id",
        "risk_score",
        "classification",
        "threat_intelligence"
    ]

    missing_fields = [
        field for field in required_fields
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
    # Validate threat intelligence
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

    required_threat_fields = [
        "total_urls",
        "malicious_count",
        "suspicious_count",
        "harmless_count",
        "undetected_count",
        "url_results"
    ]

    missing_threat_fields = [
        field for field in required_threat_fields
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
    # Data received successfully
    # -----------------------------------------

    print("Received validated data:")
    print(json.dumps(data, indent=4))

    return JsonResponse(
        {
            "status": "success",
            "message": "Results received successfully",
            "received_data": data
        },
        status=200
    )