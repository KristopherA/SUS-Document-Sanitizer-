import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree as ET

from app.errors import ProcessingFailed, UnsupportedDocument
from app.formats import detect, safe_download_name
from app.office import strip_active_content
from app.pdf import _active_pdf_features, _contains_active_marker, _write_pdf_structure


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
    def test_odf_script_element_is_removed_entirely(self):
        content = b'''<?xml version="1.0" encoding="UTF-8"?>
        <office:document-content
          xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
          xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0">
          <office:scripts><office:script script:language="BenignTest">no-op</office:script></office:scripts>
          <office:body><office:text/></office:body>
        </office:document-content>'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.odt"
            clean = Path(directory) / "clean.odt"
            with zipfile.ZipFile(source, "w") as package:
                package.writestr("mimetype", "application/vnd.oasis.opendocument.text")
                package.writestr("content.xml", content)

            findings = strip_active_content(source, clean)

            self.assertEqual(findings, {"Scripts or event handlers"})
            with zipfile.ZipFile(clean) as package:
                root = ET.fromstring(package.read("content.xml"))
                self.assertFalse(any(element.tag.rsplit("}", 1)[-1] == "script" for element in root.iter()))

    def test_standard_package_relationship_is_not_removed_or_reported(self):
        relationships = b'''<?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="core" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
        </Relationships>'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.docx"
            clean = Path(directory) / "clean.docx"
            with zipfile.ZipFile(source, "w") as package:
                package.writestr("_rels/.rels", relationships)
                package.writestr("word/document.xml", b"<document>hello</document>")

            findings = strip_active_content(source, clean)

            self.assertEqual(findings, set())
            with zipfile.ZipFile(clean) as package:
                self.assertIn(b"core-properties", package.read("_rels/.rels"))

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
    def test_pdf_structure_uses_json_without_stream_payloads(self):
        captured_command = []

        def fake_run(command, **kwargs):
            captured_command.extend(command)
            kwargs["stdout"].write(b'{"obj:1 0 R":{"value":{"/S":"/JavaScript"}}}')
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.pdf"
            structure = Path(directory) / "structure.json"
            source.write_bytes(b"%PDF-1.7\n")
            with patch("app.pdf.subprocess.run", side_effect=fake_run):
                _write_pdf_structure(source, structure)

            self.assertIn("--json", captured_command)
            self.assertIn("--json-stream-data=none", captured_command)
            self.assertNotIn("--qdf", captured_command)
            self.assertEqual(_active_pdf_features(structure), {"PDF JavaScript"})

    def test_oversized_pdf_structure_is_rejected(self):
        def fake_run(_command, **kwargs):
            kwargs["stdout"].write(b"01234567890")
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.pdf"
            structure = Path(directory) / "structure.json"
            source.write_bytes(b"%PDF-1.7\n")
            with patch("app.pdf.MAX_PDF_INSPECTION_BYTES", 10), patch(
                "app.pdf.subprocess.run", side_effect=fake_run
            ):
                with self.assertRaisesRegex(ProcessingFailed, "structural metadata"):
                    _write_pdf_structure(source, structure)

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
