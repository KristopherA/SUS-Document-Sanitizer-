from __future__ import annotations

import os
import tempfile
from pathlib import Path

from flask import Flask, after_this_request, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

from .errors import MalwareDetected, SanitizationError, ScannerUnavailable, UnsupportedDocument
from .formats import detect, safe_download_name
from .sanitizer import sanitize


MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
MAX_FORM_MEMORY_BYTES = int(os.getenv("MAX_FORM_MEMORY_BYTES", str(64 * 1024)))
MAX_FORM_PARTS = int(os.getenv("MAX_FORM_PARTS", "4"))
TRUSTED_HOSTS = [host.strip() for host in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
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

        try:
            document_format = detect(source, uploaded.filename)
            destination = work_dir / f"clean{document_format.extension}"
            findings = sanitize(source, destination, document_format)
        except MalwareDetected as exc:
            temp_dir.cleanup()
            return render_template("index.html", error=str(exc), danger=True, max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 422
        except (UnsupportedDocument, ScannerUnavailable, SanitizationError) as exc:
            temp_dir.cleanup()
            return render_template("index.html", error=str(exc), max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 422

        download_name = safe_download_name(uploaded.filename, document_format.extension)

        @after_this_request
        def cleanup(response):
            temp_dir.cleanup()
            return response

        response = send_file(destination, as_attachment=True, download_name=download_name, max_age=0)
        response.headers["X-Sanitization-Status"] = "clean"
        response.headers["X-Sanitization-Findings"] = ", ".join(findings)
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return render_template(
            "index.html",
            error=f"The document is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
            max_size_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
        ), 413

    return app


app = create_app()
