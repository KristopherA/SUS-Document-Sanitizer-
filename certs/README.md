# TLS certificate location

Place the certificate material for your chosen hostname in this directory using these exact filenames:

- `fullchain.pem` — the server certificate followed by any intermediate certificates.
- `privkey.pem` — the unencrypted PEM private key corresponding to the certificate.

The real files are excluded by `.gitignore`. Do not commit, email, or copy the private key into an image.

Recommended host permissions:

```sh
chown root:root certs/fullchain.pem
chmod 0644 certs/fullchain.pem
chown root:101 certs/privkey.pem
chmod 0640 certs/privkey.pem
```

Group `101` allows the unprivileged nginx container to read the key. The `.example` files are intentionally invalid placeholders. The real files are required by `docker compose up`.
