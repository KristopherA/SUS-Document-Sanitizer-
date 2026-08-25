from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

from .errors import ProcessingFailed
from .formats import DocumentFormat


MAX_ARCHIVE_FILES = 10_000
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_XML_BYTES = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
PROCESS_TIMEOUT = int(os.getenv("PROCESS_TIMEOUT_SECONDS", "120"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(200 * 1024 * 1024)))

DANGEROUS_PARTS = (
    "vbaproject",
    "vbadata",
    "activex/",
    "embeddings/",
    "externallinks/",
    "customui/",
    "attachedtoolbars",
    "digitalsignatures/",
    "_xmlsignatures/",
    "scripts/",
    "basic/",
    "object ",
    "objects/",
)

DANGEROUS_REL_TYPES = (
    "vbaproject",
    "oleobject",
    "package",
    "attachedtemplate",
    "externallink",
    "control",
    "activex",
    "customui",
    "hyperlink",
)

DANGEROUS_CONTENT_TYPES = (
    "vba",
    "activex",
    "oleobject",
    "external-link",
)

DANGEROUS_FIELD = re.compile(r"\b(?:DDE|DDEAUTO)\b", re.IGNORECASE)

PART_FINDINGS = (
    (("vbaproject", "vbadata"), "Macros"),
    (("activex/",), "ActiveX controls"),
    (("embeddings/", "object ", "objects/", "oleobject", "package"), "Embedded files or objects"),
    (("externallinks/", "externallink", "attachedtemplate", "hyperlink"), "External links or data connections"),
    (("scripts/", "basic/", "customui/", "attachedtoolbars", "control"), "Scripts or event handlers"),
    (("digitalsignatures/", "_xmlsignatures/"), "Digital signatures"),
)


def _record_part_finding(value: str, findings: set[str]) -> None:
    lowered = value.lower()
    for fragments, description in PART_FINDINGS:
        if any(fragment in lowered for fragment in fragments):
            findings.add(description)


def _is_dangerous_part(name: str) -> bool:
    lowered = name.lower()
    return any(fragment in lowered for fragment in DANGEROUS_PARTS)


def _is_dangerous_relationship(rel_type: str) -> bool:
    """Match the relationship name, not words in its standards namespace URL."""
    relationship_name = rel_type.lower().rsplit("/", 1)[-1]
    return relationship_name in DANGEROUS_REL_TYPES


def _safe_zip_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _validate_archive(entries: list[zipfile.ZipInfo]) -> None:
    if len(entries) > MAX_ARCHIVE_FILES:
        raise ProcessingFailed("The document contains too many package entries.")
    total = 0
    for entry in entries:
        if not _safe_zip_name(entry.filename):
            raise ProcessingFailed("The document package contains an unsafe path.")
        total += entry.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ProcessingFailed("The expanded document is too large.")
        if entry.compress_size and entry.file_size / entry.compress_size > MAX_COMPRESSION_RATIO:
            raise ProcessingFailed("The document contains a suspiciously compressed package entry.")


def _clean_relationships(payload: bytes, findings: set[str]) -> bytes:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ProcessingFailed("A relationship file in the document is malformed.") from exc

    changed = False
    for relation in list(root):
        rel_type = relation.attrib.get("Type", "").lower()
        external = relation.attrib.get("TargetMode", "").lower() == "external"
        target = relation.attrib.get("Target", "").lower()
        if external or _is_dangerous_part(target) or _is_dangerous_relationship(rel_type):
            _record_part_finding(f"{rel_type} {target}", findings)
            if external:
                findings.add("External links or data connections")
            root.remove(relation)
            changed = True
    return _serialize_xml(root, payload) if changed else payload


def _clean_content_types(payload: bytes, findings: set[str]) -> bytes:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ProcessingFailed("The document content-type index is malformed.") from exc

    changed = False
    for item in list(root):
        part = item.attrib.get("PartName", "").lower()
        content_type = item.attrib.get("ContentType", "").lower()
        if _is_dangerous_part(part) or any(value in content_type for value in DANGEROUS_CONTENT_TYPES):
            _record_part_finding(f"{part} {content_type}", findings)
            root.remove(item)
            changed = True
    return _serialize_xml(root, payload) if changed else payload


def _serialize_xml(root: ET.Element, original: bytes) -> bytes:
    """Serialize XML while retaining the package's namespace prefixes."""
    try:
        for _event, namespace in ET.iterparse(BytesIO(original), events=("start-ns",)):
            prefix, uri = namespace
            if not re.fullmatch(r"ns\d+", prefix or ""):
                ET.register_namespace(prefix or "", uri)
    except (ET.ParseError, ValueError):
        pass
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _clean_document_xml(payload: bytes, findings: set[str]) -> bytes:
    # DDE fields are commands stored as text inside otherwise ordinary document XML.
    if len(payload) > MAX_XML_BYTES:
        raise ProcessingFailed("An XML component in the document is too large to inspect safely.")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return payload
    changed = False
    # Remove active elements from their parent. Clearing an ODF office:script
    # node leaves an invalid empty shell because its language is required.
    for parent in root.iter():
        for child in list(parent):
            child_name = child.tag.rsplit("}", 1)[-1].lower() if isinstance(child.tag, str) else ""
            if child_name in {"event-listener", "script"}:
                parent.remove(child)
                findings.add("Scripts or event handlers")
                changed = True
    for element in root.iter():
        if element.text and DANGEROUS_FIELD.search(element.text):
            element.text = "[unsafe dynamic field removed]"
            findings.add("Dynamic DDE fields")
            changed = True
        for attribute in list(element.attrib):
            attribute_name = attribute.rsplit("}", 1)[-1].lower()
            value = element.attrib[attribute]
            if attribute_name in {"href", "macro-name", "event-name"} and (
                attribute_name != "href"
                or value.lower().startswith(("http:", "https:", "file:", "ftp:", "javascript:", "data:"))
            ):
                del element.attrib[attribute]
                findings.add("External links or data connections" if attribute_name == "href" else "Scripts or event handlers")
                changed = True
    return _serialize_xml(root, payload) if changed else payload


def strip_active_content(source: Path, destination: Path) -> set[str]:
    """Create an inert package for LibreOffice to reconstruct."""
    findings: set[str] = set()
    try:
        with zipfile.ZipFile(source, "r") as incoming:
            entries = incoming.infolist()
            _validate_archive(entries)
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as outgoing:
                # ODF requires `mimetype` to be the first, uncompressed entry.
                ordered_entries = sorted(entries, key=lambda item: item.filename != "mimetype")
                for entry in ordered_entries:
                    name = entry.filename
                    if entry.is_dir() or _is_dangerous_part(name):
                        if not entry.is_dir():
                            _record_part_finding(name, findings)
                        continue
                    payload = incoming.read(entry)
                    lowered = name.lower()
                    if lowered.endswith(".rels"):
                        payload = _clean_relationships(payload, findings)
                    elif lowered == "[content_types].xml":
                        payload = _clean_content_types(payload, findings)
                    elif lowered.endswith(".xml"):
                        payload = _clean_document_xml(payload, findings)

                    clean_entry = zipfile.ZipInfo(name, date_time=entry.date_time)
                    clean_entry.compress_type = zipfile.ZIP_STORED if name == "mimetype" else zipfile.ZIP_DEFLATED
                    clean_entry.external_attr = 0o600 << 16
                    outgoing.writestr(clean_entry, payload)
    except zipfile.BadZipFile as exc:
        raise ProcessingFailed("The Office document package is invalid.") from exc
    return findings


def _run(command: list[str], description: str, home: Path) -> None:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=PROCESS_TIMEOUT,
            check=False,
            env={**os.environ, "HOME": str(home)},
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProcessingFailed(f"{description} timed out; the document was rejected.") from exc
    if result.returncode != 0:
        raise ProcessingFailed(f"{description} failed; the document may be damaged or password-protected.")


def sanitize_office(source: Path, destination: Path, document_format: DocumentFormat) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="office-") as work_dir_name:
        work_dir = Path(work_dir_name)
        stripped = work_dir / f"input{document_format.extension}"
        output_dir = work_dir / "output"
        profile_dir = work_dir / "profile"
        home_dir = work_dir / "home"
        output_dir.mkdir()
        profile_dir.mkdir()
        home_dir.mkdir()

        findings = strip_active_content(source, stripped)
        _run(
            [
                "libreoffice",
                "--headless",
                "--nologo",
                "--nodefault",
                "--nolockcheck",
                "--norestore",
                "--invisible",
                "--safe-mode",
                f"-env:UserInstallation=file://{profile_dir}",
                "--convert-to",
                f"{document_format.extension.removeprefix('.')}:{document_format.libreoffice_filter}",
                "--outdir",
                str(output_dir),
                str(stripped),
            ],
            "Office document reconstruction",
            home_dir,
        )

        rebuilt = output_dir / stripped.name
        if not rebuilt.is_file() or rebuilt.stat().st_size == 0:
            raise ProcessingFailed("LibreOffice did not produce a reconstructed document.")
        if rebuilt.stat().st_size > MAX_OUTPUT_BYTES:
            raise ProcessingFailed("The reconstructed document is too large to return safely.")

        # A second package pass verifies the rebuilt output and removes anything
        # the converter unexpectedly retained or generated.
        verified = work_dir / f"verified{document_format.extension}"
        findings.update(strip_active_content(rebuilt, verified))
        if verified.stat().st_size > MAX_OUTPUT_BYTES:
            raise ProcessingFailed("The verified document is too large to return safely.")
        shutil.copyfile(verified, destination)
        return sorted(findings)
