import unittest
from io import BytesIO
from unittest.mock import patch

try:
    from app.web import create_app
except ModuleNotFoundError as exc:
    if exc.name != "flask":
        raise
    create_app = None


@unittest.skipIf(create_app is None, "Flask is not installed outside the service image")
class SanitizationResponseTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_clean_download_reports_removed_issues(self):
        def fake_sanitize(_source, destination, _document_format):
            destination.write_bytes(b"%PDF-1.7\nclean")
            return ["PDF JavaScript", "PDF launch actions"]

        with patch("app.web.sanitize", side_effect=fake_sanitize):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\nsource"), "report.pdf")},
                content_type="multipart/form-data",
            )
        self.addCleanup(response.close)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Sanitization-Status"], "clean")
        self.assertEqual(response.headers["X-Sanitization-Findings"], "PDF JavaScript, PDF launch actions")
        self.assertEqual(response.data, b"%PDF-1.7\nclean")

    def test_clean_download_can_report_no_active_content(self):
        def fake_sanitize(_source, destination, _document_format):
            destination.write_bytes(b"%PDF-1.7\nclean")
            return []

        with patch("app.web.sanitize", side_effect=fake_sanitize):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\nsource"), "report.pdf")},
                content_type="multipart/form-data",
            )
        self.addCleanup(response.close)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Sanitization-Status"], "clean")
        self.assertEqual(response.headers["X-Sanitization-Findings"], "")


if __name__ == "__main__":
    unittest.main()
