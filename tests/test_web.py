import unittest
from io import BytesIO
from unittest.mock import patch

try:
    from app.errors import ProcessingFailed, ScannerUnavailable
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


if __name__ == "__main__":
    unittest.main()
