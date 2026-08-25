# Document Sanitizer

A small, unauthenticated internal web service for uploading a suspicious document and downloading a reconstructed version in the same modern document format.

The service is intentionally fail-closed: if antivirus is unavailable, the file is malformed, reconstruction fails, or active content remains, no download is returned.

## What it does

1. Validates the extension against the actual file structure.
2. Streams the original to ClamAV using its `INSTREAM` protocol.
3. Removes macros, embedded packages and objects, ActiveX controls, external relationships, scripts, event handlers, DDE fields, and digital-signature components from modern Office/OpenDocument packages.
4. Reconstructs Office documents with LibreOffice running headlessly with macros disabled.
5. Reconstructs PDFs through Ghostscript's `pdfwrite` device.
6. Expands and inspects reconstructed PDFs for JavaScript, automatic actions, launch actions, embedded files, XFA, and rich media.
7. Structurally validates the result and scans it with ClamAV again.
8. Returns the clean file and deletes both temporary copies after the response.

Supported formats: `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, and `.odp`.

Legacy binary and macro-enabled formats (`.doc`, `.xls`, `.ppt`, `.docm`, `.xlsm`, `.pptm`) are rejected. Returning those formats safely would risk preserving executable content. Users must first save them as their corresponding modern non-macro format.

## Run it

Requirements: Docker Engine with the Compose plugin, at least 4 GB of available memory, and enough disk space for ClamAV signatures.

```sh
docker compose up --build -d
```

Open `http://localhost:8080`. The first start can take several minutes while ClamAV downloads and loads its signatures.

Stop it with:

```sh
docker compose down
```

ClamAV signatures are kept in the `clamav_signatures` Docker volume. Uploaded documents are stored only in the sanitizer container's temporary in-memory filesystem.

The ClamAV stream limit is configured above the web upload limit so every accepted upload can be fully scanned rather than silently truncated.

## Optional HTTPS certificate

An optional nginx TLS proxy is defined in `compose.https.yaml`. The standard deployment does not start it, so the sanitizer continues working while certificate material is absent.

1. Copy the certificate chain for your chosen hostname to `certs/fullchain.pem`.
2. Copy its matching private key to `certs/privkey.pem`.
3. Point the chosen DNS hostname at this server.
4. Start the TLS deployment, replacing the sample hostname if needed:

```sh
SANITIZER_HOSTNAME=sanitizer.example.org docker compose -f compose.yaml -f compose.https.yaml up --build -d
```

The proxy listens on ports 80 and 443, redirects HTTP to HTTPS, and forwards HTTPS uploads to the sanitizer. Real certificate and key files are excluded by `.gitignore`; only deliberately invalid `.example` stubs are included.

## Deployment boundaries

This service deliberately has no application login or API key. Do **not** expose it directly to the public internet. Publish it only on a trusted staff network or behind an existing access-controlled reverse proxy. Add firewall rate limits if many staff share the service.

The container is read-only, runs as an unprivileged user, drops Linux capabilities, uses an in-memory temporary filesystem, and has CPU, memory, and process limits. It never receives the Docker socket or a host document directory.

For higher-risk environments, run this Compose project on a dedicated disposable VM, deny unnecessary outbound network traffic from the VM, and rebuild the images regularly so LibreOffice, Ghostscript, qpdf, Python, and ClamAV remain patched.

## Security and fidelity limitations

No sanitizer can prove that an arbitrary document is harmless. Antivirus is signature-based, and document parsers can themselves contain vulnerabilities. This service reduces risk by removing active features and rebuilding files; it does not certify them as safe.

The output keeps the same file type and generally preserves visible layout, text, images, and styles. Interactive forms, hyperlinks, embedded files, external data connections, macros, scripts, signatures, multimedia, and some annotations are intentionally removed. Complicated documents may have small formatting changes after reconstruction. If pixel-perfect output is more important than editability, a Dangerzone-style rasterized PDF is the safer design.

Password-protected or damaged documents are rejected.

## Configuration

Settings are in `compose.yaml`:

- `MAX_UPLOAD_BYTES`: maximum request size; default 50 MB.
- `PROCESS_TIMEOUT_SECONDS`: reconstruction timeout; default 120 seconds.
- `CLAMAV_TIMEOUT_SECONDS`: optional antivirus scan timeout; default 120 seconds.
- `SANITIZER_PORT`: HTTP host port; default 8080.
- `SANITIZER_HOSTNAME`: hostname used by the optional HTTPS proxy; default `sanitizer.example.org`.
- `SANITIZER_HTTP_PORT` and `SANITIZER_HTTPS_PORT`: optional proxy ports; defaults 80 and 443.

## Tests

The package-level tests use only Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

For a full integration check, build and run the containers, submit representative documents, and verify them with your organization's approved test corpus. The EICAR antivirus test file must be rejected, but it should only be used in accordance with your security team's procedures.
