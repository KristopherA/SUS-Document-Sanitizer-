import hashlib
import unittest
from io import BytesIO
from unittest.mock import patch

try:
    from app.errors import MalwareDetected, ProcessingFailed, ScannerUnavailable
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
        self.assertEqual(
            response.headers["X-Original-SHA256"],
            hashlib.sha256(b"%PDF-1.7\nsource").hexdigest(),
        )
        self.assertEqual(
            response.headers["X-Clean-SHA256"],
            hashlib.sha256(b"%PDF-1.7\nclean").hexdigest(),
        )
        self.assertEqual(response.headers["X-Original-Size"], str(len(b"%PDF-1.7\nsource")))
        self.assertRegex(response.headers["X-Sanitization-Time"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
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

    def test_twenty_megabyte_document_is_below_upload_limit(self):
        def fake_sanitize(_source, destination, _document_format):
            destination.write_bytes(b"%PDF-1.7\nclean")
            return []

        document = b"%PDF-1.7\n" + b"x" * (20 * 1024 * 1024)
        with patch("app.web.sanitize", side_effect=fake_sanitize):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(document), "large-report.pdf")},
                content_type="multipart/form-data",
            )
        self.addCleanup(response.close)
        self.addCleanup(response.request.input_stream.close)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"%PDF-1.7\nclean")

    def test_document_size_is_enforced_after_multipart_parsing(self):
        one_megabyte = 1024 * 1024
        with (
            patch("app.web.MAX_UPLOAD_BYTES", one_megabyte),
            patch("app.web.sanitize") as sanitize_mock,
        ):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\n" + b"x" * (2 * one_megabyte)), "oversized.pdf")},
                content_type="multipart/form-data",
            )
        self.addCleanup(response.close)
        self.addCleanup(response.request.input_stream.close)

        self.assertEqual(response.status_code, 413)
        self.assertIn(b"larger than the 1 MB limit", response.data)
        sanitize_mock.assert_not_called()

    def test_picker_offers_drag_and_drop(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="drop-zone"', response.data)
        self.assertIn(b"or drag and drop it here", response.data)
        self.assertIn(
            b'id="security-team-notice" class="security-team-notice" role="alert" hidden',
            response.data,
        )
        self.assertIn(
            b'id="incident-report" class="incident-report" aria-labelledby="incident-report-title" hidden',
            response.data,
        )
        self.assertIn(b'id="copy-report-button"', response.data)
        self.assertIn(b"Copy this report", response.data)

        script = self.client.get("/static/app.js")
        self.addCleanup(script.close)
        self.assertIn(b"Document Sanitizer Processing Report", script.data)
        self.assertIn(b'Issues found and removed: ${safeReportValue(findings, "None detected")}', script.data)
        self.assertIn(b'findings ? "Incident report" : "Processing report"', script.data)

    def test_malware_detection_shows_security_team_analysis_notice(self):
        with patch("app.web.sanitize", side_effect=MalwareDetected("Malware was detected.")):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\nsource"), "report.pdf")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 422)
        self.assertIn(
            b'id="security-team-notice" class="security-team-notice" role="alert">The original document should be sent to your IT or security team for further analysis.',
            response.data,
        )
        self.assertIn(b"Document Sanitizer Incident Report", response.data)
        self.assertIn(
            b'id="incident-report" class="incident-report" aria-labelledby="incident-report-title">',
            response.data,
        )
        self.assertIn(b"Outcome: Rejected because antivirus detected malware", response.data)
        self.assertIn(hashlib.sha256(b"%PDF-1.7\nsource").hexdigest().encode(), response.data)
        self.assertIn(b"Recommended action: The original document should be sent to your IT or security team", response.data)

    def test_unsanitizable_document_shows_discard_notice(self):
        with patch("app.web.sanitize", side_effect=ProcessingFailed("The document could not be rebuilt safely.")):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\nsource"), "report.pdf")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 422)
        self.assertIn(b"The document could not be rebuilt safely.", response.data)
        self.assertIn(b"Discard this document.", response.data)
        self.assertIn(b"Document Sanitizer Incident Report", response.data)
        self.assertIn(b"Outcome: Rejected because the document could not be sanitized safely", response.data)
        self.assertIn(hashlib.sha256(b"%PDF-1.7\nsource").hexdigest().encode(), response.data)

    def test_scanner_outage_does_not_show_discard_notice(self):
        with patch("app.web.sanitize", side_effect=ScannerUnavailable("The scanner is temporarily unavailable.")):
            response = self.client.post(
                "/sanitize",
                data={"document": (BytesIO(b"%PDF-1.7\nsource"), "report.pdf")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 422)
        self.assertIn(b"The scanner is temporarily unavailable.", response.data)
        self.assertNotIn(b"Discard this document.", response.data)
        self.assertIn(b"Document Sanitizer Incident Report", response.data)
        self.assertIn(b"Outcome: Not processed because the antivirus scanner was unavailable", response.data)
        self.assertIn(hashlib.sha256(b"%PDF-1.7\nsource").hexdigest().encode(), response.data)


if __name__ == "__main__":
    unittest.main()
