from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, after_this_request, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

from .errors import MalwareDetected, SanitizationError, ScannerUnavailable, UnsupportedDocument
from .formats import detect, safe_download_name
from .sanitizer import sanitize


MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", str(64 * 1024 * 1024)))
MAX_FORM_MEMORY_BYTES = int(os.getenv("MAX_FORM_MEMORY_BYTES", "500000"))
MAX_FORM_PARTS = int(os.getenv("MAX_FORM_PARTS", "4"))
TRUSTED_HOSTS = [host.strip() for host in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]
SECURITY_TEAM_INSTRUCTION = "The original document should be sent to your IT or security team for further analysis."


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as document:
        while chunk := document.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _report_filename(filename: str) -> str:
    basename = Path(filename.replace("\\", "/")).name
    printable = "".join(character for character in basename if character.isprintable())
    return printable[:255] or "document"


def _rejection_report(
    filename: str,
    size: int,
    sha256: str,
    detected_at: str,
    details: str,
) -> str:
    return "\n".join(
        (
            "Document Sanitizer Incident Report",
            f"Detection time (UTC): {detected_at}",
            f"Original filename: {_report_filename(filename)}",
            f"Original size: {size} bytes",
            f"Original SHA-256: {sha256}",
            "Outcome: Rejected because antivirus detected malware",
            f"Details: {details}",
            f"Recommended action: {SECURITY_TEAM_INSTRUCTION}",
        )
    )


def create_app() -> Flask:
    app = Flask(__name__)
    if MAX_REQUEST_BYTES <= MAX_UPLOAD_BYTES:
        raise RuntimeError("MAX_REQUEST_BYTES must be greater than MAX_UPLOAD_BYTES")
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.config["MAX_FORM_MEMORY_SIZE"] = MAX_FORM_MEMORY_BYTES
    app.config["MAX_FORM_PARTS"] = MAX_FORM_PARTS
    app.config["TRUSTED_HOSTS"] = TRUSTED_HOSTS

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html", max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/sanitize")
    def sanitize_upload():
        uploaded = request.files.get("document")
        if uploaded is None or not uploaded.filename:
            return render_template("index.html", error="Choose a document to upload.", max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 400

        temp_dir = tempfile.TemporaryDirectory(prefix="upload-")
        work_dir = Path(temp_dir.name)
        source = work_dir / "incoming"
        uploaded.save(source)

        original_size = source.stat().st_size
        if original_size > MAX_UPLOAD_BYTES:
            temp_dir.cleanup()
            return render_template(
                "index.html",
                error=f"The document is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
            ), 413

        detected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        original_sha256 = _sha256(source)

        try:
            document_format = detect(source, uploaded.filename)
            destination = work_dir / f"clean{document_format.extension}"
            findings = sanitize(source, destination, document_format)
        except MalwareDetected as exc:
            temp_dir.cleanup()
            return render_template(
                "index.html",
                error=str(exc),
                danger=True,
                discard=True,
                security_team_notice=True,
                incident_report=_rejection_report(
                    uploaded.filename,
                    original_size,
                    original_sha256,
                    detected_at,
                    str(exc),
                ),
                max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
            ), 422
        except ScannerUnavailable as exc:
            temp_dir.cleanup()
            return render_template("index.html", error=str(exc), max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 422
        except (UnsupportedDocument, SanitizationError) as exc:
            temp_dir.cleanup()
            return render_template("index.html", error=str(exc), discard=True, max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 422

        download_name = safe_download_name(uploaded.filename, document_format.extension)

        @after_this_request
        def cleanup(response):
            temp_dir.cleanup()
            return response

        response = send_file(destination, as_attachment=True, download_name=download_name, max_age=0)
        response.headers["X-Sanitization-Status"] = "clean"
        response.headers["X-Sanitization-Findings"] = ", ".join(findings)
        response.headers["X-Sanitization-Time"] = detected_at
        response.headers["X-Original-Size"] = str(original_size)
        response.headers["X-Original-SHA256"] = original_sha256
        response.headers["X-Clean-SHA256"] = _sha256(destination)
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        request_size = request.content_length
        if request_size is not None and request_size > MAX_REQUEST_BYTES:
            message = (
                f"The upload request is larger than the {MAX_REQUEST_BYTES // (1024 * 1024)} MB request limit. "
                f"Documents are limited to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
            )
        else:
            message = "The upload form could not be parsed safely. The document was not processed."
        return render_template(
            "index.html",
            error=message,
            max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
        ), 413

    return app


app = create_app()
