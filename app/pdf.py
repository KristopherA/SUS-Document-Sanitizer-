from __future__ import annotations

import os
import re
import tempfile
import subprocess
from pathlib import Path

from .errors import ProcessingFailed


PROCESS_TIMEOUT = int(os.getenv("PROCESS_TIMEOUT_SECONDS", "120"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(200 * 1024 * 1024)))
ACTIVE_PDF_MARKERS = re.compile(
    rb"/(JavaScript|JS|OpenAction|AA|Launch|RichMedia|EmbeddedFiles|XFA)\b",
    re.IGNORECASE,
)

PDF_FINDINGS = {
    b"javascript": "PDF JavaScript",
    b"js": "PDF JavaScript",
    b"openaction": "Automatic PDF actions",
    b"aa": "Automatic PDF actions",
    b"launch": "PDF launch actions",
    b"richmedia": "Rich media",
    b"embeddedfiles": "Embedded files",
    b"xfa": "XFA forms",
}


def _active_pdf_features(path: Path) -> set[str]:
    """Identify active features in an expanded PDF without loading it all into memory."""
    findings: set[str] = set()
    overlap = b""
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            payload = overlap + chunk
            for match in ACTIVE_PDF_MARKERS.finditer(payload):
                findings.add(PDF_FINDINGS[match.group(1).lower()])
            overlap = payload[-128:]
    return findings


def _contains_active_marker(path: Path) -> bool:
    return bool(_active_pdf_features(path))


def _expand_for_inspection(source: Path, destination: Path) -> None:
    try:
        expansion = subprocess.run(
            ["qpdf", "--qdf", "--object-streams=disable", str(source), str(destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProcessingFailed("The PDF inspection timed out; the document was rejected.") from exc
    if expansion.returncode not in (0, 3) or not destination.is_file():
        raise ProcessingFailed("The PDF could not be inspected safely.")
    if destination.stat().st_size > MAX_OUTPUT_BYTES:
        raise ProcessingFailed("The expanded PDF is too large to inspect safely.")


def sanitize_pdf(source: Path, destination: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="pdf-source-check-") as source_check_dir:
        expanded_source = Path(source_check_dir) / "expanded.pdf"
        _expand_for_inspection(source, expanded_source)
        findings = _active_pdf_features(expanded_source)

    command = [
        "gs",
        "-q",
        "-dSAFER",
        "-dBATCH",
        "-dNOPAUSE",
        "-dCompatibilityLevel=1.7",
        "-sDEVICE=pdfwrite",
        "-dDetectDuplicateImages=true",
        "-dCompressFonts=true",
        "-dPreserveAnnots=false",
        "-dPrinted=false",
        f"-sOutputFile={destination}",
        str(source),
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=PROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProcessingFailed("PDF reconstruction timed out; the document was rejected.") from exc

    if result.returncode != 0 or not destination.is_file() or destination.stat().st_size == 0:
        raise ProcessingFailed("PDF reconstruction failed; the document may be damaged or password-protected.")
    if destination.stat().st_size > MAX_OUTPUT_BYTES:
        raise ProcessingFailed("The reconstructed PDF is too large to return safely.")

    validation = subprocess.run(
        ["qpdf", "--check", str(destination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    if validation.returncode not in (0, 3):
        raise ProcessingFailed("The reconstructed PDF did not pass structural validation.")

    # Expand object streams before looking for active PDF dictionaries; direct
    # byte searching can miss names hidden inside compressed object streams.
    with tempfile.TemporaryDirectory(prefix="pdf-check-") as check_dir:
        expanded = Path(check_dir) / "expanded.pdf"
        _expand_for_inspection(destination, expanded)
        if _contains_active_marker(expanded):
            raise ProcessingFailed("Active PDF content remained after reconstruction, so the document was rejected.")
    return sorted(findings)
