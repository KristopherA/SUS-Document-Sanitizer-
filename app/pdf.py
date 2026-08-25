from __future__ import annotations

import os
import re
import tempfile
import subprocess
from pathlib import Path

from .errors import ProcessingFailed


PROCESS_TIMEOUT = int(os.getenv("PROCESS_TIMEOUT_SECONDS", "120"))
ACTIVE_PDF_MARKERS = re.compile(
    rb"/(?:JavaScript|JS|OpenAction|AA|Launch|RichMedia|EmbeddedFiles|XFA)\b",
    re.IGNORECASE,
)


def sanitize_pdf(source: Path, destination: Path) -> None:
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
        expansion = subprocess.run(
            ["qpdf", "--qdf", "--object-streams=disable", str(destination), str(expanded)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        if expansion.returncode not in (0, 3) or not expanded.is_file():
            raise ProcessingFailed("The reconstructed PDF could not be inspected safely.")
        if ACTIVE_PDF_MARKERS.search(expanded.read_bytes()):
            raise ProcessingFailed("Active PDF content remained after reconstruction, so the document was rejected.")
