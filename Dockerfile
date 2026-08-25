FROM python:3.13-slim-trixie@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-dejavu-core \
        fonts-liberation2 \
        ghostscript \
        libreoffice-calc \
        libreoffice-impress \
        libreoffice-writer \
        qpdf \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sanitizer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --requirement requirements.txt \
    && pip uninstall --yes setuptools wheel pip

COPY app ./app
COPY gunicorn.conf.py .

USER sanitizer

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app.web:app"]
