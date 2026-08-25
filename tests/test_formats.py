import tempfile
import unittest
import zipfile
from pathlib import Path

from app.errors import UnsupportedDocument
from app.formats import detect, safe_download_name
from app.office import strip_active_content


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

            strip_active_content(source, clean)

            with zipfile.ZipFile(clean) as package:
                names = package.namelist()
                self.assertNotIn("word/vbaProject.bin", names)
                self.assertNotIn("word/embeddings/payload.exe", names)
                self.assertNotIn(b"evil.invalid", package.read("_rels/.rels"))
                self.assertNotIn(b"vbaProject", package.read("[Content_Types].xml"))


if __name__ == "__main__":
    unittest.main()
