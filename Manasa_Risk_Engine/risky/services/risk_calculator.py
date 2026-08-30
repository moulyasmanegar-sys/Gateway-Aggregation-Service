class RiskCalculator:

    # ============================================================
    # RISK WEIGHTS
    # ============================================================

    SUSPICIOUS_KEYWORD_WEIGHT = 8
    SUSPICIOUS_KEYWORD_MAX_SCORE = 30

    IOC_WEIGHT = 3
    IOC_MAX_SCORE = 15

    MALICIOUS_WEIGHT = 5
    MALICIOUS_MAX_SCORE = 15

    SUSPICIOUS_WEIGHT = 3
    SUSPICIOUS_MAX_SCORE = 10

    HARMLESS_REDUCTION = 1
    HARMLESS_MAX_REDUCTION = 10

    # ============================================================
    # CALCULATE RISK
    # ============================================================

    @classmethod
    def calculate(
        cls,
        ai_risk="LOW",
        ioc_count=0,
        malicious_count=0,
        suspicious_count=0,
        harmless_count=0,
        suspicious_keyword_count=0,
    ):

        # ========================================================
        # SUSPICIOUS KEYWORD SCORE
        # ========================================================

        keyword_score = min(
            int(suspicious_keyword_count)
            * cls.SUSPICIOUS_KEYWORD_WEIGHT,
            cls.SUSPICIOUS_KEYWORD_MAX_SCORE
        )

        # ========================================================
        # TOTAL IOC SCORE
        # ========================================================

        ioc_score = min(
            int(ioc_count)
            * cls.IOC_WEIGHT,
            cls.IOC_MAX_SCORE
        )

        # ========================================================
        # MALICIOUS IOC SCORE
        # ========================================================

        malicious_score = min(
            int(malicious_count)
            * cls.MALICIOUS_WEIGHT,
            cls.MALICIOUS_MAX_SCORE
        )

        # ========================================================
        # SUSPICIOUS IOC SCORE
        # ========================================================

        suspicious_score = min(
            int(suspicious_count)
            * cls.SUSPICIOUS_WEIGHT,
            cls.SUSPICIOUS_MAX_SCORE
        )

        # ========================================================
        # HARMLESS IOC REDUCTION
        # ========================================================

        harmless_reduction = min(
            int(harmless_count)
            * cls.HARMLESS_REDUCTION,
            cls.HARMLESS_MAX_REDUCTION
        )

        # ========================================================
        # FINAL RISK SCORE
        # ========================================================

        risk_score = (
            keyword_score
            + ioc_score
            + malicious_score
            + suspicious_score
            - harmless_reduction
        )

        # ========================================================
        # KEEP SCORE BETWEEN 0 AND 100
        # ========================================================

        risk_score = max(
            0,
            min(risk_score, 100)
        )

        # ========================================================
        # RISK LEVEL
        # ========================================================

        if risk_score >= 70:
            risk_level = "HIGH"

        elif risk_score >= 40:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        # ========================================================
        # RETURN RESULT
        # ========================================================

        return {
            "risk_score": risk_score,

            "risk_level": risk_level,

            "score_breakdown": {
                "keyword_score": keyword_score,
                "ioc_score": ioc_score,
                "malicious_score": malicious_score,
                "suspicious_score": suspicious_score,
                "harmless_reduction": harmless_reduction,
            },

            "ioc_statistics": {
                "total_iocs": int(ioc_count),
                "malicious_iocs": int(malicious_count),
                "suspicious_iocs": int(suspicious_count),
                "harmless_iocs": int(harmless_count),
            }
        }