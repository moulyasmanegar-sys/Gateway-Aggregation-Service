from risk_classifier import classify_risk
def generate_report(analysis):

    # --------------------------------------------------
    # Validate input
    # --------------------------------------------------

    if not isinstance(analysis, dict):
        raise ValueError("Input must be a JSON object/dictionary")

    # --------------------------------------------------
    # Read values from Risk Engine input
    # --------------------------------------------------

    indicator = analysis.get("indicator")
    indicator_type = analysis.get("indicator_type")
    risk_score = analysis.get("risk_score")

    # --------------------------------------------------
    # Validate required fields
    # --------------------------------------------------

    if indicator is None:
        raise ValueError("Missing required field: indicator")

    if indicator_type is None:
        raise ValueError("Missing required field: indicator_type")

    if risk_score is None:
        raise ValueError("Missing required field: risk_score")

    # Make sure risk score is numeric
    try:

        risk_score = float(risk_score)

    except (TypeError, ValueError):

        raise ValueError(
            "risk_score must be a number"
        )

    # --------------------------------------------------
    # Classify Risk
    # --------------------------------------------------

    risk_level = classify_risk(risk_score)

    # --------------------------------------------------
    # Judgement Call
    # --------------------------------------------------

    if risk_level == "LOW":

        verdict = "SAFE"

        action = "ALLOW"

        recommendation = (
            "No significant threat indicators were detected. "
            "The indicator appears safe based on the available analysis."
        )


    elif risk_level == "MEDIUM":

        verdict = "SUSPICIOUS"

        action = "REVIEW"

        recommendation = (
            "The indicator has suspicious characteristics. "
            "Exercise caution and perform further investigation."
        )


    else:

        verdict = "HIGH RISK"

        action = "BLOCK"

        recommendation = (
            "Do not interact with this indicator. "
            "Security investigation is recommended."
        )


    # --------------------------------------------------
    # Final Report JSON
    # --------------------------------------------------

    report = {

        "indicator": indicator,

        "indicator_type": indicator_type,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "verdict": verdict,

        "action": action,

        "recommendation": recommendation

    }


    return report


# --------------------------------------------------
# Test
# --------------------------------------------------

if __name__ == "__main__":

    test_input = {

        "indicator": "http://test-example.com",

        "indicator_type": "URL",

        "risk_score": 85

    }


    report = generate_report(test_input)


    print("\nGENERATED REPORT")
    print("----------------")

    for key, value in report.items():

        print(f"{key}: {value}")