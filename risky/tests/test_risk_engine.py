from django.test import TestCase

from risky.services.classifier import RiskClassifier
from risky.services.risk_calculator import RiskCalculator


class RiskEngineTestCase(TestCase):

    def test_high_risk_email(self):

        result = RiskCalculator.calculate(
            ai_risk="HIGH",
            ioc_count=4,
            malicious_count=12,
            suspicious_count=3,
            harmless_count=0,
        )

        classification = RiskClassifier.classify(
            result["risk_score"]
        )

        self.assertEqual(
            classification,
            "MALICIOUS"
        )

    def test_safe_email(self):

        result = RiskCalculator.calculate(
            ai_risk="LOW",
            ioc_count=0,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=10,
        )

        classification = RiskClassifier.classify(
            result["risk_score"]
        )

        self.assertEqual(
            classification,
            "SAFE"
        )

    def test_suspicious_email(self):

        result = RiskCalculator.calculate(
            ai_risk="MEDIUM",
            ioc_count=2,
            malicious_count=0,
            suspicious_count=1,
            harmless_count=0,
        )

        classification = RiskClassifier.classify(
            result["risk_score"]
        )

        self.assertEqual(
            classification,
            "SUSPICIOUS"
        )