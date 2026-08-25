from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import UnsupportedDocument


PDF_MAGIC = b"%PDF-"
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
ZIP_MAGIC = b"PK\x03\x04"


@dataclass(frozen=True)
class DocumentFormat:
    extension: str
    kind: str
    libreoffice_filter: str | None = None


FORMATS = {
    ".pdf": DocumentFormat(".pdf", "pdf"),
    ".docx": DocumentFormat(".docx", "office", "Office Open XML Text"),
    ".xlsx": DocumentFormat(".xlsx", "office", "Calc MS Excel 2007 XML"),
    ".pptx": DocumentFormat(".pptx", "office", "Impress MS PowerPoint 2007 XML"),
    ".odt": DocumentFormat(".odt", "office", "writer8"),
    ".ods": DocumentFormat(".ods", "office", "calc8"),
    ".odp": DocumentFormat(".odp", "office", "impress8"),
}

EXPECTED_MARKERS = {
    ".docx": ("word/document.xml",),
    ".xlsx": ("xl/workbook.xml",),
    ".pptx": ("ppt/presentation.xml",),
    ".odt": ("mimetype", "content.xml"),
    ".ods": ("mimetype", "content.xml"),
    ".odp": ("mimetype", "content.xml"),
}

SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


def safe_download_name(original: str, extension: str) -> str:
    name = Path(original).name
    stem = SAFE_NAME.sub("_", Path(name).stem).strip(" ._") or "document"
    return f"{stem}-clean{extension}"


def detect(path: Path, supplied_name: str) -> DocumentFormat:
    extension = Path(supplied_name).suffix.lower()
    document_format = FORMATS.get(extension)
    if document_format is None:
        if extension in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}:
            raise UnsupportedDocument(
                "Legacy and macro-enabled Office files are not returned in their original format because doing so can preserve active code. "
                "Save the file as DOCX, XLSX, or PPTX first."
            )
        raise UnsupportedDocument("Supported file types are PDF, DOCX, XLSX, PPTX, ODT, ODS, and ODP.")

    with path.open("rb") as source:
        magic = source.read(8)

    if document_format.kind == "pdf":
        if not magic.startswith(PDF_MAGIC):
            raise UnsupportedDocument("The file extension says PDF, but its contents are not a PDF.")
        return document_format

    if magic.startswith(OLE_MAGIC):
        raise UnsupportedDocument("The file is a legacy binary Office document and cannot be safely returned in the same format.")
    if not magic.startswith(ZIP_MAGIC):
        raise UnsupportedDocument("The Office document is not a valid modern document package.")

    try:
        with zipfile.ZipFile(path) as package:
            names = set(package.namelist())
            if not all(marker in names for marker in EXPECTED_MARKERS[extension]):
                raise UnsupportedDocument("The file contents do not match its document extension.")
    except (zipfile.BadZipFile, OSError) as exc:
        raise UnsupportedDocument("The Office document package is damaged or invalid.") from exc

    return document_format

