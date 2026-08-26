import requests
from unittest.mock import Mock, patch

from django.test import TestCase
from rest_framework.test import APIClient

from risky.serializers import (
    EmailDataSerializer,
    RiskInputSerializer,
)
from risky.views import clean_email, clean_url
from risky.services.ioc_extractor import IOCExtractor
from risky.services.risk_calculator import RiskCalculator
from risky.services.classifier import RiskClassifier
from risky.services.virustotal_service import VirusTotalService


# ============================================================
# SERIALIZER TESTS
# ============================================================

class EmailDataSerializerTests(TestCase):

    def test_valid_email_data(self):
        data = {
            "id": 14,
            "sender": "sender@gmail.com",
            "receiver": "receiver@gmail.com",
            "subject": "Test Email",
            "body": "This is a test email.",
            "urls": [
                "https://example.com"
            ],
        }

        serializer = EmailDataSerializer(data=data)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data["sender"],
            "sender@gmail.com"
        )

    def test_invalid_sender_email(self):
        data = {
            "sender": "invalid-email",
            "receiver": "receiver@gmail.com",
            "subject": "Test",
            "body": "Test body",
        }

        serializer = EmailDataSerializer(data=data)

        self.assertFalse(serializer.is_valid())

        self.assertIn(
            "sender",
            serializer.errors
        )

    def test_missing_required_fields(self):
        data = {
            "sender": "sender@gmail.com"
        }

        serializer = EmailDataSerializer(data=data)

        self.assertFalse(serializer.is_valid())

        self.assertIn(
            "receiver",
            serializer.errors
        )

        self.assertIn(
            "subject",
            serializer.errors
        )

        self.assertIn(
            "body",
            serializer.errors
        )

    def test_valid_url_list(self):
        data = {
            "sender": "sender@gmail.com",
            "receiver": "receiver@gmail.com",
            "subject": "Test",
            "body": "Test body",
            "urls": [
                "https://example.com",
                "https://google.com",
            ],
        }

        serializer = EmailDataSerializer(data=data)

        self.assertTrue(serializer.is_valid())


class RiskInputSerializerTests(TestCase):

    def test_valid_risk_input(self):
        data = {
            "message": "Email Stored",
            "email_id": 14,
            "urls": [
                "https://example.com"
            ],
            "data": {
                "id": 14,
                "sender": "sender@gmail.com",
                "receiver": "receiver@gmail.com",
                "subject": "Test Email",
                "body": "Visit https://example.com",
                "urls": [
                    "https://example.com"
                ],
            },
        }

        serializer = RiskInputSerializer(data=data)

        self.assertTrue(serializer.is_valid())

    def test_missing_email_id(self):
        data = {
            "message": "Email Stored",
            "urls": [],
            "data": {
                "sender": "sender@gmail.com",
                "receiver": "receiver@gmail.com",
                "subject": "Test",
                "body": "Test body",
            },
        }

        serializer = RiskInputSerializer(data=data)

        self.assertFalse(serializer.is_valid())

        self.assertIn(
            "email_id",
            serializer.errors
        )

    def test_invalid_url(self):
        data = {
            "email_id": 14,
            "urls": [
                "not-a-valid-url"
            ],
            "data": {
                "sender": "sender@gmail.com",
                "receiver": "receiver@gmail.com",
                "subject": "Test",
                "body": "Test",
            },
        }

        serializer = RiskInputSerializer(data=data)

        self.assertFalse(serializer.is_valid())

        self.assertIn(
            "urls",
            serializer.errors
        )


# ============================================================
# EMAIL / URL CLEANING TESTS
# ============================================================

class CleaningFunctionTests(TestCase):

    def test_clean_normal_email(self):
        result = clean_email(
            "moulya@gmail.com"
        )

        self.assertEqual(
            result,
            "moulya@gmail.com"
        )

    def test_clean_mailto_email(self):
        result = clean_email(
            "[moulya@gmail.com](mailto:moulya@gmail.com)"
        )

        self.assertEqual(
            result,
            "moulya@gmail.com"
        )

    def test_clean_empty_email(self):
        result = clean_email("")

        self.assertEqual(
            result,
            ""
        )

    def test_clean_normal_url(self):
        result = clean_url(
            "https://example.com/test"
        )

        self.assertEqual(
            result,
            "https://example.com/test"
        )

    def test_clean_markdown_url(self):
        result = clean_url(
            "[https://example.com/test](https://example.com/test)"
        )

        self.assertEqual(
            result,
            "https://example.com/test"
        )

    def test_clean_empty_url(self):
        result = clean_url("")

        self.assertEqual(
            result,
            ""
        )


# ============================================================
# IOC EXTRACTOR TESTS
# ============================================================

class IOCExtractorTests(TestCase):

    def test_extract_url(self):
        result = IOCExtractor.extract(
            subject="Test",
            body="Visit https://example.com"
        )

        self.assertIn(
            "https://example.com",
            result["urls"]
        )

    def test_extract_multiple_urls(self):
        result = IOCExtractor.extract(
            subject="Links",
            body=(
                "https://example.com "
                "https://google.com"
            )
        )

        self.assertEqual(
            len(result["urls"]),
            2
        )

    def test_remove_duplicate_urls(self):
        result = IOCExtractor.extract(
            subject="Test",
            body=(
                "https://example.com "
                "https://example.com"
            )
        )

        self.assertEqual(
            len(result["urls"]),
            1
        )

    def test_extract_domain(self):
        result = IOCExtractor.extract(
            subject="Test",
            body="Visit https://example.com/test"
        )

        self.assertIn(
            "example.com",
            result["domains"]
        )

    def test_detect_suspicious_keyword(self):
        result = IOCExtractor.extract(
            subject="Urgent Action Required",
            body="Please login immediately."
        )

        self.assertIn(
            "urgent",
            result["suspicious_keywords"]
        )

        self.assertIn(
            "login",
            result["suspicious_keywords"]
        )

    def test_keyword_detection_is_case_insensitive(self):
        result = IOCExtractor.extract(
            subject="URGENT",
            body="Please LOGIN immediately."
        )

        self.assertIn(
            "urgent",
            result["suspicious_keywords"]
        )

        self.assertIn(
            "login",
            result["suspicious_keywords"]
        )

    def test_ioc_count(self):
        result = IOCExtractor.extract(
            subject="Urgent",
            body="Visit https://example.com"
        )

        self.assertEqual(
            result["ioc_count"],
            2
        )

    def test_empty_content(self):
        result = IOCExtractor.extract(
            subject="",
            body=""
        )

        self.assertEqual(
            result["urls"],
            []
        )

        self.assertEqual(
            result["domains"],
            []
        )

        self.assertEqual(
            result["suspicious_keywords"],
            []
        )

        self.assertEqual(
            result["ioc_count"],
            0
        )


# ============================================================
# RISK CALCULATOR TESTS
# ============================================================

class RiskCalculatorTests(TestCase):

    def test_low_ai_risk(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW"
        )

        self.assertEqual(
            result["score_breakdown"]["ai_score"],
            20
        )

    def test_medium_ai_risk(self):
        result = RiskCalculator.calculate(
            ai_risk="MEDIUM"
        )

        self.assertEqual(
            result["score_breakdown"]["ai_score"],
            40
        )

    def test_high_ai_risk(self):
        result = RiskCalculator.calculate(
            ai_risk="HIGH"
        )

        self.assertEqual(
            result["score_breakdown"]["ai_score"],
            60
        )

    def test_ioc_score(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            ioc_count=2
        )

        self.assertEqual(
            result["score_breakdown"]["ioc_score"],
            6
        )

    def test_ioc_score_maximum(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            ioc_count=100
        )

        self.assertEqual(
            result["score_breakdown"]["ioc_score"],
            15
        )

    def test_malicious_score(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            malicious_count=2
        )

        self.assertEqual(
            result["score_breakdown"]["malicious_score"],
            10
        )

    def test_malicious_score_maximum(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            malicious_count=100
        )

        self.assertEqual(
            result["score_breakdown"]["malicious_score"],
            15
        )

    def test_suspicious_score(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            suspicious_count=2
        )

        self.assertEqual(
            result["score_breakdown"]["suspicious_score"],
            6
        )

    def test_suspicious_score_maximum(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            suspicious_count=100
        )

        self.assertEqual(
            result["score_breakdown"]["suspicious_score"],
            10
        )

    def test_harmless_reduction(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            harmless_count=5
        )

        self.assertEqual(
            result["score_breakdown"]["harmless_reduction"],
            5
        )

    def test_harmless_reduction_maximum(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            harmless_count=100
        )

        self.assertEqual(
            result["score_breakdown"]["harmless_reduction"],
            10
        )

    def test_risk_score_cannot_go_below_zero(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            harmless_count=100
        )

        self.assertGreaterEqual(
            result["risk_score"],
            0
        )

    def test_risk_score_cannot_exceed_100(self):
        result = RiskCalculator.calculate(
            ai_risk="HIGH",
            ioc_count=100,
            malicious_count=100,
            suspicious_count=100
        )

        self.assertLessEqual(
            result["risk_score"],
            100
        )

    def test_low_risk_level(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW"
        )

        self.assertEqual(
            result["risk_level"],
            "LOW"
        )

    def test_medium_risk_level(self):
        result = RiskCalculator.calculate(
            ai_risk="MEDIUM"
        )

        self.assertEqual(
            result["risk_level"],
            "MEDIUM"
        )

    def test_high_risk_level(self):
        result = RiskCalculator.calculate(
            ai_risk="HIGH",
            malicious_count=2
        )

        self.assertEqual(
            result["risk_level"],
            "HIGH"
        )

    def test_url_statistics(self):
        result = RiskCalculator.calculate(
            ai_risk="LOW",
            malicious_count=2,
            suspicious_count=3,
            harmless_count=4,
            total_urls=9
        )

        self.assertEqual(
            result["url_statistics"]["total_urls"],
            9
        )

        self.assertEqual(
            result["url_statistics"]["malicious_urls"],
            2
        )

        self.assertEqual(
            result["url_statistics"]["suspicious_urls"],
            3
        )

        self.assertEqual(
            result["url_statistics"]["harmless_urls"],
            4
        )


# ============================================================
# CLASSIFIER TESTS
# ============================================================

class RiskClassifierTests(TestCase):

    def test_safe_classification(self):
        self.assertEqual(
            RiskClassifier.classify(39),
            "SAFE"
        )

    def test_suspicious_lower_boundary(self):
        self.assertEqual(
            RiskClassifier.classify(40),
            "SUSPICIOUS"
        )

    def test_suspicious_classification(self):
        self.assertEqual(
            RiskClassifier.classify(69),
            "SUSPICIOUS"
        )

    def test_malicious_lower_boundary(self):
        self.assertEqual(
            RiskClassifier.classify(70),
            "MALICIOUS"
        )

    def test_malicious_classification(self):
        self.assertEqual(
            RiskClassifier.classify(100),
            "MALICIOUS"
        )


# ============================================================
# VIRUSTOTAL SERVICE TESTS
# ============================================================

class VirusTotalServiceTests(TestCase):

    @patch("risky.services.virustotal_service.settings")
    def test_api_key_is_required(self, mock_settings):

        mock_settings.VIRUSTOTAL_API_KEY = ""

        with self.assertRaises(ValueError):
            VirusTotalService()

    @patch("risky.services.virustotal_service.settings")
    def test_service_creates_headers(self, mock_settings):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        service = VirusTotalService()

        self.assertEqual(
            service.headers["x-apikey"],
            "test-api-key"
        )

        self.assertEqual(
            service.headers["Accept"],
            "application/json"
        )

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_successful_url_analysis(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id-123"
            }
        }

        analysis_response = Mock()

        analysis_response.raise_for_status.return_value = None

        analysis_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 58,
                        "undetected": 34,
                    }
                }
            }
        }

        mock_post.return_value = submit_response
        mock_get.return_value = analysis_response

        service = VirusTotalService()

        result = service.analyze_url(
            "https://example.com"
        )

        self.assertEqual(
            result["url"],
            "https://example.com"
        )

        self.assertEqual(
            result["malicious"],
            0
        )

        self.assertEqual(
            result["suspicious"],
            0
        )

        self.assertEqual(
            result["harmless"],
            58
        )

        self.assertEqual(
            result["undetected"],
            34
        )

        mock_post.assert_called_once()
        mock_get.assert_called_once()

    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_submission_failure(
        self,
        mock_settings,
        mock_post
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        response = Mock()

        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized"
        )

        mock_post.return_value = response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "VirusTotal URL submission failed",
            str(context.exception)
        )

    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_submission_timeout(
        self,
        mock_settings,
        mock_post
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        mock_post.side_effect = (
            requests.exceptions.Timeout()
        )

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "timed out",
            str(context.exception)
        )

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_invalid_submission_json(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.side_effect = ValueError()

        mock_post.return_value = submit_response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "invalid JSON",
            str(context.exception)
        )

        mock_get.assert_not_called()

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_missing_analysis_id(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {}
        }

        mock_post.return_value = submit_response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "analysis ID",
            str(context.exception)
        )

        mock_get.assert_not_called()

    @patch("risky.services.virustotal_service.time.sleep")
    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_analysis_failed(
        self,
        mock_settings,
        mock_post,
        mock_get,
        mock_sleep
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id"
            }
        }

        analysis_response = Mock()

        analysis_response.raise_for_status.return_value = None

        analysis_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "failed"
                }
            }
        }

        mock_post.return_value = submit_response
        mock_get.return_value = analysis_response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "VirusTotal analysis failed",
            str(context.exception)
        )

        mock_sleep.assert_not_called()

    @patch("risky.services.virustotal_service.time.sleep")
    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_analysis_timeout(
        self,
        mock_settings,
        mock_post,
        mock_get,
        mock_sleep
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id"
            }
        }

        analysis_response = Mock()

        analysis_response.raise_for_status.return_value = None

        analysis_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "queued"
                }
            }
        }

        mock_post.return_value = submit_response
        mock_get.return_value = analysis_response

        service = VirusTotalService()

        result = service.analyze_url(
            "https://example.com"
        )

        self.assertEqual(
            result["url"],
            "https://example.com"
        )

        self.assertEqual(
            result["undetected"],
            1
        )

        self.assertEqual(
            mock_get.call_count,
            5
        )

        self.assertEqual(
            mock_sleep.call_count,
            4
        )

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_analysis_invalid_json(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id"
            }
        }

        analysis_response = Mock()

        analysis_response.raise_for_status.return_value = None

        analysis_response.json.side_effect = ValueError()

        mock_post.return_value = submit_response
        mock_get.return_value = analysis_response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "invalid",
            str(context.exception).lower()
        )

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_analysis_request_timeout(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id"
            }
        }

        mock_post.return_value = submit_response

        mock_get.side_effect = (
            requests.exceptions.Timeout()
        )

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "timed out",
            str(context.exception)
        )

    @patch("risky.services.virustotal_service.requests.get")
    @patch("risky.services.virustotal_service.requests.post")
    @patch("risky.services.virustotal_service.settings")
    def test_analysis_request_failure(
        self,
        mock_settings,
        mock_post,
        mock_get
    ):

        mock_settings.VIRUSTOTAL_API_KEY = "test-api-key"

        submit_response = Mock()

        submit_response.raise_for_status.return_value = None

        submit_response.json.return_value = {
            "data": {
                "id": "analysis-id"
            }
        }

        mock_post.return_value = submit_response

        response = Mock()

        response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError(
                "500 Server Error"
            )
        )

        mock_get.return_value = response

        service = VirusTotalService()

        with self.assertRaises(Exception) as context:
            service.analyze_url(
                "https://example.com"
            )

        self.assertIn(
            "VirusTotal analysis request failed",
            str(context.exception)
        )


# ============================================================
# RISK ENGINE API TESTS
# ============================================================

class RiskAnalysisAPITests(TestCase):

    def setUp(self):
        self.client = APIClient()

        self.valid_payload = {
            "message": "Email Stored",
            "email_id": 14,
            "urls": [
                "https://example.com"
            ],
            "data": {
                "id": 14,
                "sender": "sender@gmail.com",
                "receiver": "receiver@gmail.com",
                "subject": "Test Email",
                "body": (
                    "Please visit "
                    "https://example.com"
                ),
                "urls": [
                    "https://example.com"
                ],
            },
        }

    @patch("risky.views.requests.post")
    @patch("risky.views.VirusTotalService")
    @patch("risky.views.IOCExtractor.extract")
    def test_risk_engine_success(
        self,
        mock_ioc,
        mock_virus_total,
        mock_thakshi
    ):

        mock_ioc.return_value = {
            "urls": [
                "https://example.com"
            ],
            "domains": [
                "example.com"
            ],
            "suspicious_keywords": [],
            "ioc_count": 1,
        }

        virus_total_instance = Mock()

        virus_total_instance.analyze_url.return_value = {
            "url": "https://example.com",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 58,
            "undetected": 34,
        }

        mock_virus_total.return_value = (
            virus_total_instance
        )

        thakshi_response = Mock()

        thakshi_response.status_code = 200

        thakshi_response.text = (
            '{"status":"success"}'
        )

        thakshi_response.raise_for_status.return_value = None

        mock_thakshi.return_value = (
            thakshi_response
        )

        response = self.client.post(
            "/api/risk-engine/analyze/",
            self.valid_payload,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        self.assertTrue(
            response.data["success"]
        )

        self.assertEqual(
            response.data["email_id"],
            14
        )

        self.assertIn(
            "risk_analysis",
            response.data
        )

        self.assertIn(
            "threat_intelligence",
            response.data
        )

        mock_virus_total.assert_called_once()

        virus_total_instance.analyze_url.assert_called_once_with(
            "https://example.com"
        )

        mock_thakshi.assert_called_once()

    @patch("risky.views.VirusTotalService")
    @patch("risky.views.IOCExtractor.extract")
    def test_virus_total_failure_returns_502(
        self,
        mock_ioc,
        mock_virus_total
    ):

        mock_ioc.return_value = {
            "urls": [
                "https://example.com"
            ],
            "domains": [
                "example.com"
            ],
            "suspicious_keywords": [],
            "ioc_count": 1,
        }

        virus_total_instance = Mock()

        virus_total_instance.analyze_url.side_effect = (
            Exception(
                "VirusTotal API unauthorized"
            )
        )

        mock_virus_total.return_value = (
            virus_total_instance
        )

        response = self.client.post(
            "/api/risk-engine/analyze/",
            self.valid_payload,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            502
        )

        self.assertFalse(
            response.data["success"]
        )

        self.assertEqual(
            response.data["email_id"],
            14
        )

        self.assertIn(
            "VirusTotal",
            response.data["error"]
        )

    def test_invalid_api_input(self):

        invalid_payload = {
            "message": "Email Stored",
            "email_id": "invalid",
            "urls": [],
            "data": {
                "sender": "sender@gmail.com",
                "receiver": "receiver@gmail.com",
                "subject": "Test",
                "body": "Test body",
            },
        }

        response = self.client.post(
            "/api/risk-engine/analyze/",
            invalid_payload,
            format="json"
        )

        self.assertEqual(
            response.status_code,
            400
        )