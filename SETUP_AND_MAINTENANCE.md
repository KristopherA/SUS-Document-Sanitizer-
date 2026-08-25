# Setup, maintenance, and upgrade guide

This guide covers installing, operating, upgrading, and rolling back the generic document sanitizer. All commands assume the shell is in the project root (this directory).

## 1. Understand what is stored

The service consists of a web sanitizer, ClamAV, and an nginx proxy. The HTTPS configuration adds a second nginx proxy for TLS.

- Uploaded and rebuilt documents exist only in the sanitizer container's temporary in-memory filesystem and are deleted after processing.
- ClamAV signatures persist in the Docker volume named `clamav_signatures`.
- TLS certificates remain on the host under `certs/` and are mounted read-only.
- Application settings and container definitions remain in the project folder.

There are no uploaded documents to back up. Back up the project configuration and TLS material; the ClamAV signature volume can be downloaded again.

## 2. Host requirements

Use a maintained Linux server or VM dedicated to this workload where practical. It needs:

- Docker Engine and the Docker Compose plugin.
- At least 4 GB of available memory.
- Sufficient disk space for Docker images and ClamAV signatures.
- Correct system time and DNS.
- Outbound HTTPS/DNS for image retrieval and ClamAV signature updates.
- Inbound access only from the intended staff network or an access-controlled reverse proxy.

Confirm Docker is ready:

```sh
docker version
docker compose version
docker info
```

Do not publish this unauthenticated service directly to the public internet.

## 3. Initial setup

### Local-only HTTP setup

Validate and start the default service:

```sh
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

The first start may take several minutes while ClamAV retrieves and loads signatures. When all services are healthy, open `http://localhost:8080` on the host.

The default proxy listens only on `127.0.0.1`. To make HTTP available on a trusted internal network, set `SANITIZER_BIND_ADDRESS`, `SANITIZER_HTTP_HOSTNAME`, and `SANITIZER_TRUSTED_HOSTS` together. HTTPS is preferred for normal staff use.

### HTTPS setup

Install the real certificate using these exact names:

```text
certs/fullchain.pem
certs/privkey.pem
```

Set host permissions so the key is not generally readable:

```sh
chmod 0644 certs/fullchain.pem
chmod 0600 certs/privkey.pem
```

Validate that the certificate and key contain the same public key:

```sh
openssl x509 -in certs/fullchain.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl sha256
openssl pkey -in certs/privkey.pem -pubout -outform DER | openssl sha256
```

The two hashes must match.

Create the DNS record before starting HTTPS. Then start the HTTPS deployment, replacing the sample hostname with the real one:

```sh
SANITIZER_HOSTNAME=sanitizer.example.org docker compose -f compose.yaml -f compose.https.yaml config --quiet
SANITIZER_HOSTNAME=sanitizer.example.org docker compose -f compose.yaml -f compose.https.yaml up --build -d
```

Allow inbound TCP ports 80 and 443 only from the intended network. Do not expose port 8080 externally when using the TLS proxy.

## 4. Acceptance checks

After setup or any upgrade:

```sh
docker compose ps
docker compose logs --tail 100 sanitizer clamav
```

For local HTTP:

```sh
curl -fsS http://127.0.0.1:8080/health
```

For HTTPS:

```sh
curl -fsS https://sanitizer.example.org/health
```

The health response should be `{"status":"ok"}`. Also verify in a browser that:

1. The upload page loads over the intended hostname.
2. A known-clean file of every supported type can be cleaned and downloaded.
3. The downloaded extension matches the original extension.
4. A controlled document containing removable active content reports what was removed.
5. A malformed or unreconstructable document is rejected and displays **Discard this document**.
6. An organization-approved EICAR test is rejected by ClamAV.

Use EICAR and other security test files only under the security team's test procedure. Never use live malware.

## 5. Routine maintenance

### Daily automated work

ClamAV updates its signatures from inside its container and stores them in the persistent signature volume. The service fails closed if antivirus is unavailable.

Check container health and recent antivirus activity:

```sh
docker compose ps
docker compose logs --since 24h clamav
docker compose exec clamav clamdscan --version
```

Investigate immediately if ClamAV is unhealthy, signatures stop updating, disk space is exhausted, or the sanitizer repeatedly restarts.

### Weekly checks

```sh
docker compose ps
docker compose logs --since 7d --no-color sanitizer clamav http-proxy
docker system df
```

For an HTTPS deployment, also review the TLS proxy:

```sh
docker compose -f compose.yaml -f compose.https.yaml logs --since 7d --no-color tls-proxy
```

Review errors, rejected processing jobs, resource pressure, restart loops, and certificate warnings. Do not collect or retain uploaded documents for troubleshooting unless the organization's handling policy explicitly permits it.

### Monthly checks

- Install security updates for the host operating system and Docker.
- Review free disk space, memory, and host alerts.
- Confirm the HTTPS certificate has sufficient remaining validity.
- Review upstream security notices for Python, Flask, Gunicorn, nginx, ClamAV, LibreOffice, Ghostscript, and qpdf.
- Rebuild and test the service so operating-system packages inside the images receive fixes.
- Run the approved clean and malicious-feature test corpus.

Inspect certificate dates:

```sh
openssl s_client -connect sanitizer.example.org:443 -servername sanitizer.example.org </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer
```

## 6. Backups and recovery material

Before an upgrade, preserve:

- The complete project folder or a versioned source-control revision.
- The active environment settings and Compose overrides.
- The TLS certificate chain and private key in an encrypted, access-controlled backup.
- The currently working sanitizer and ClamAV images.

Tag the working images before rebuilding:

```sh
docker image tag generic-document-sanitizer:local generic-document-sanitizer:rollback
docker image tag generic-document-sanitizer-clamav:local generic-document-sanitizer-clamav:rollback
```

Do not back up temporary container files. The ClamAV signature volume is optional recovery material because it is automatically repopulated.

## 7. Safe application upgrade procedure

Perform upgrades first on a staging host when available.

### Step 1: Record the current state

```sh
docker compose ps
docker compose images
docker compose config > /secure/maintenance/deployed-compose.txt
```

Replace `/secure/maintenance/` with an access-controlled location outside the project folder. Store the file with the maintenance record, not in a public repository. Save the working source revision and tag the images as described above.

### Step 2: Update dependencies deliberately

Python packages are declared in `requirements.in` and locked with versions and hashes in `requirements.txt`.

1. Change the direct versions in `requirements.in`.
2. Review release notes and security advisories.
3. Regenerate the lock:

```sh
uv pip compile requirements.in --upgrade --generate-hashes --output-file requirements.txt
```

4. Review every changed transitive dependency and hash before building.

Container bases are digest-pinned:

- Python in `Dockerfile`.
- ClamAV in `Dockerfile.clamav`.
- nginx in both `compose.yaml` and `compose.https.yaml`.

To upgrade one, select a supported upstream release, obtain its current digest from the official registry, and update both the tag and digest. Keep the nginx reference identical in both Compose files. Never remove digest pinning merely to obtain automatic updates.

LibreOffice, Ghostscript, qpdf, and system libraries come from the pinned Python base distribution. A no-cache rebuild installs the current packages available for that base. Move to a newer supported base deliberately when the existing distribution approaches end of support.

### Step 3: Validate configuration and code

```sh
docker compose config --quiet
docker compose -f compose.yaml -f compose.https.yaml config --quiet
python3 -m unittest discover -s tests -v
```

The host Python run may skip web tests if Flask is not installed. The next container test runs the full suite using the application image.

### Step 4: Build fresh images

```sh
docker compose build --pull --no-cache sanitizer clamav
```

Review the build output for failures and unexpected repository changes.

### Step 5: Run all tests in the built image

```sh
docker compose run --rm --no-deps -v "$PWD/tests:/app/tests:ro" sanitizer python -W error::ResourceWarning -m unittest discover -s tests -v
```

Do not deploy unless every test passes.

### Step 6: Deploy during a maintenance window

For local HTTP:

```sh
docker compose up -d
```

For HTTPS, using the real hostname:

```sh
SANITIZER_HOSTNAME=sanitizer.example.org docker compose -f compose.yaml -f compose.https.yaml up -d
```

Wait for ClamAV and the sanitizer to become healthy, then perform all acceptance checks.

### Step 7: Observe before cleanup

Keep rollback images until the service has processed the approved test corpus and operated normally through the organization's observation period. Remove obsolete images only after rollback is no longer required.

Do not use `docker system prune --volumes`; it can remove recovery material and the signature database.

## 8. Certificate renewal

1. Obtain the renewed certificate from the approved certificate process.
2. Confirm its hostname, issuer, validity period, and matching key.
3. Back up the existing certificate and key securely.
4. Replace the files under `certs/` while retaining their exact names and permissions.
5. Recreate only the TLS proxy so it opens the new certificate files:

```sh
SANITIZER_HOSTNAME=sanitizer.example.org docker compose -f compose.yaml -f compose.https.yaml up -d --force-recreate tls-proxy
```

6. Confirm the served certificate dates with `openssl s_client` and test the HTTPS health endpoint.

The sanitizer and ClamAV do not need to restart for certificate-only renewal.

## 9. Rollback

Rollback is appropriate if health checks fail, documents no longer reconstruct correctly, antivirus cannot scan, or the acceptance corpus regresses.

1. Restore the previous project files and configuration.
2. Restore the prior image tags:

```sh
docker image tag generic-document-sanitizer:rollback generic-document-sanitizer:local
docker image tag generic-document-sanitizer-clamav:rollback generic-document-sanitizer-clamav:local
```

3. Recreate the services without building:

```sh
docker compose up -d --no-build --force-recreate
```

For HTTPS, include both Compose files and the hostname. Then repeat health and acceptance checks. Preserve failed-version logs for analysis, but do not preserve uploaded documents unless policy permits it.

## 10. Troubleshooting

### ClamAV stays unhealthy

```sh
docker compose logs --tail 200 clamav
docker compose exec clamav clamdscan --version
docker system df
```

Check outbound DNS/HTTPS, available memory and disk, and whether the signature volume is writable. Do not bypass antivirus to restore service; the sanitizer is designed to stop when scanning is unavailable.

If the signature database is confirmed corrupt, stop the project before replacing its volume. Deleting the volume is destructive and forces a full signature download, so obtain change approval and identify the exact Compose volume first.

### Sanitizer is unhealthy

```sh
docker compose logs --tail 200 sanitizer
docker compose exec sanitizer python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read().decode())"
```

Check whether ClamAV is healthy, whether container limits are being reached, and whether the current images passed tests.

### HTTPS fails

```sh
docker compose -f compose.yaml -f compose.https.yaml logs --tail 200 tls-proxy
openssl x509 -in certs/fullchain.pem -noout -subject -issuer -dates
```

Confirm DNS, firewall rules, exact certificate paths, permissions, matching public-key hashes, and `SANITIZER_HOSTNAME`.

### Uploads are rejected unexpectedly

Confirm the file is one of `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, or `.odp`; the content matches its extension; it is not password-protected; and it is within configured limits. Review sanitizer and ClamAV logs without copying the suspicious document onto an administrator workstation.

## 11. Recommended maintenance record

For each change, record:

- Date, operator, reason, and approved change reference.
- Previous and new application source revisions.
- Previous and new Python, Python-base, ClamAV, and nginx versions/digests.
- Test results and tested file types.
- Deployment start/end time and service interruption.
- Health, certificate, and antivirus verification.
- Rollback tags and the date they may be removed.
- Any errors or formatting regressions observed.
