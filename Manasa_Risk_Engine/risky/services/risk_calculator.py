class RiskCalculator:

    AI_RISK_SCORES = {
        "LOW": 20,
        "MEDIUM": 40,
        "HIGH": 60,
    }

    IOC_WEIGHT = 3
    IOC_MAX_SCORE = 15

    MALICIOUS_WEIGHT = 5
    MALICIOUS_MAX_SCORE = 15

    SUSPICIOUS_WEIGHT = 3
    SUSPICIOUS_MAX_SCORE = 10
    HARMLESS_REDUCTION = 1
    HARMLESS_MAX_REDUCTION = 10
    @classmethod
    def calculate(
        cls,
        ai_risk="LOW",
        ioc_count=0,
        malicious_count=0,
        suspicious_count=0,
        harmless_count=0,
        total_urls=0,
    ):
        """
        Calculate the final risk score.

        Final score range: 0 to 100.
        """

        # -----------------------------
        # AI RISK SCORE
        # -----------------------------
        ai_score = cls.AI_RISK_SCORES.get(
            str(ai_risk).upper(),
            0
        )

        # -----------------------------
        # IOC SCORE
        # -----------------------------
        ioc_score = min(
            int(ioc_count) * cls.IOC_WEIGHT,
            cls.IOC_MAX_SCORE
        )

        # -----------------------------
        # MALICIOUS URL SCORE
        # -----------------------------
        malicious_score = min(
            int(malicious_count) * cls.MALICIOUS_WEIGHT,
            cls.MALICIOUS_MAX_SCORE
        )

        # -----------------------------
        # SUSPICIOUS URL SCORE
        # -----------------------------
        suspicious_score = min(
            int(suspicious_count) * cls.SUSPICIOUS_WEIGHT,
            cls.SUSPICIOUS_MAX_SCORE
        )

        # -----------------------------
        # HARMLESS URL REDUCTION
        # -----------------------------
        harmless_reduction = min(
            int(harmless_count) * cls.HARMLESS_REDUCTION,
            cls.HARMLESS_MAX_REDUCTION
        )

        # -----------------------------
        # URL PRESENCE
        # -----------------------------
        # If URLs exist but VirusTotal does not
        # classify them as malicious/suspicious,
        # do not add extra risk.
        url_score = 0

        # -----------------------------
        # FINAL SCORE
        # -----------------------------
        risk_score = (
            ai_score
            + ioc_score
            + malicious_score
            + suspicious_score
            + url_score
            - harmless_reduction
        )

        # Keep score between 0 and 100
        risk_score = max(
            0,
            min(risk_score, 100)
        )

        # -----------------------------
        # RISK LEVEL
        # -----------------------------
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "score_breakdown": {
                "ai_score": ai_score,
                "ioc_score": ioc_score,
                "malicious_score": malicious_score,
                "suspicious_score": suspicious_score,
                "harmless_reduction": harmless_reduction,
                "url_score": url_score,
            },

            "url_statistics": {
                "total_urls": int(total_urls),
                "malicious_urls": int(malicious_count),
                "suspicious_urls": int(suspicious_count),
                "harmless_urls": int(harmless_count),
            }
        }