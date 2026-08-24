class RiskClassifier:

    @staticmethod
    def classify(risk_score):

        if risk_score >= 70:
            return "MALICIOUS"

        if risk_score >= 40:
            return "SUSPICIOUS"

        return "SAFE"