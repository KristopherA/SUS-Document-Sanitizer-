from __future__ import annotations

from pathlib import Path

from . import clamav
from .formats import DocumentFormat
from .office import sanitize_office
from .pdf import sanitize_pdf


def sanitize(source: Path, destination: Path, document_format: DocumentFormat) -> None:
    clamav.scan(source)
    if document_format.kind == "pdf":
        sanitize_pdf(source, destination)
    else:
        sanitize_office(source, destination, document_format)
    clamav.scan(destination)

