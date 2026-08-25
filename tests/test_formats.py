import tempfile
import unittest
import zipfile
from pathlib import Path

from app.errors import ProcessingFailed, UnsupportedDocument
from app.formats import detect, safe_download_name
from app.office import strip_active_content
from app.pdf import _active_pdf_features, _contains_active_marker


class FormatTests(unittest.TestCase):
    def test_safe_download_name(self):
        self.assertEqual(safe_download_name("../../Board minutes (final).docx", ".docx"), "Board minutes _final-clean.docx")

    def test_extension_content_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"%PDF-1.7\n")
            with self.assertRaises(UnsupportedDocument):
                detect(path, "report.docx")

    def test_pdf_is_detected_by_magic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"%PDF-1.7\n")
            self.assertEqual(detect(path, "report.pdf").kind, "pdf")


class OfficePackageTests(unittest.TestCase):
    def test_archive_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.docx"
            clean = Path(directory) / "clean.docx"
            with zipfile.ZipFile(source, "w") as package:
                package.writestr("../outside", b"payload")

            with self.assertRaises(ProcessingFailed):
                strip_active_content(source, clean)

    def test_active_parts_and_external_relationships_are_removed(self):
        relationships = b'''<?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="safe" Type="officeDocument" Target="word/document.xml"/>
          <Relationship Id="bad" Type="hyperlink" Target="https://evil.invalid/payload" TargetMode="External"/>
        </Relationships>'''
        content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Override PartName="/word/document.xml" ContentType="document"/>
          <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
        </Types>'''

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.docx"
            clean = Path(directory) / "clean.docx"
            with zipfile.ZipFile(source, "w") as package:
                package.writestr("[Content_Types].xml", content_types)
                package.writestr("_rels/.rels", relationships)
                package.writestr("word/document.xml", b"<document>hello</document>")
                package.writestr("word/vbaProject.bin", b"malicious macro")
                package.writestr("word/embeddings/payload.exe", b"MZ")

            findings = strip_active_content(source, clean)

            self.assertEqual(
                findings,
                {"Embedded files or objects", "External links or data connections", "Macros"},
            )

            with zipfile.ZipFile(clean) as package:
                names = package.namelist()
                self.assertNotIn("word/vbaProject.bin", names)
                self.assertNotIn("word/embeddings/payload.exe", names)
                self.assertNotIn(b"evil.invalid", package.read("_rels/.rels"))
                self.assertNotIn(b"vbaProject", package.read("[Content_Types].xml"))


class PdfInspectionTests(unittest.TestCase):
    def test_active_marker_across_read_boundary_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "expanded.pdf"
            path.write_bytes(b"A" * (1024 * 1024 - 4) + b"/JavaScript action")
            self.assertTrue(_contains_active_marker(path))

    def test_active_pdf_features_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "expanded.pdf"
            path.write_bytes(b"%PDF-1.7 /JavaScript /Launch /EmbeddedFiles")
            self.assertEqual(
                _active_pdf_features(path),
                {"Embedded files", "PDF JavaScript", "PDF launch actions"},
            )


if __name__ == "__main__":
    unittest.main()
