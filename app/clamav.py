from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

from .errors import MalwareDetected, ScannerUnavailable


CHUNK_SIZE = 64 * 1024


def scan(path: Path) -> None:
    """Stream a file to clamd and fail closed on errors."""
    host = os.getenv("CLAMAV_HOST", "clamav")
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    timeout = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "120"))

    try:
        with socket.create_connection((host, port), timeout=timeout) as client:
            client.settimeout(timeout)
            client.sendall(b"zINSTREAM\0")
            with path.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    client.sendall(struct.pack("!I", len(chunk)))
                    client.sendall(chunk)
            client.sendall(struct.pack("!I", 0))

            response = bytearray()
            while True:
                part = client.recv(4096)
                if not part:
                    break
                response.extend(part)
                if b"\0" in part:
                    break
    except (OSError, ValueError) as exc:
        raise ScannerUnavailable("The malware scanner is unavailable; the document was not processed.") from exc

    result = bytes(response).rstrip(b"\0\n").decode("utf-8", errors="replace")
    if result.endswith(" FOUND"):
        signature = result.rsplit(": ", 1)[-1].removesuffix(" FOUND")
        raise MalwareDetected(f"Malware was detected ({signature}). The document was rejected.")
    if not result.endswith(" OK"):
        raise ScannerUnavailable("The malware scanner could not verify the document; it was rejected.")

