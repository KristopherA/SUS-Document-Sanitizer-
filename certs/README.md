# TLS certificate location

Place the certificate material for your chosen hostname in this directory using these exact filenames:

- `fullchain.pem` — the server certificate followed by any intermediate certificates.
- `privkey.pem` — the unencrypted PEM private key corresponding to the certificate.

The real files are excluded by `.gitignore`. Do not commit, email, or copy the private key into an image.

Recommended host permissions:

```sh
chmod 0644 certs/fullchain.pem
chmod 0600 certs/privkey.pem
```

The `.example` files are intentionally invalid placeholders. The HTTPS proxy will not be started by the normal `docker compose up` command.
