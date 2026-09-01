# ---------------------------------------------------------------------------
# PR-CAMPUS backend
#
# Includes the system libraries WeasyPrint needs for PDF rendering, plus the
# open-source scanners the platform integrates (nmap, nuclei, whatweb) so the
# Standard and Comprehensive profiles work out of the box.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- system dependencies -----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      # WeasyPrint (PDF rendering)
      libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
      libffi-dev shared-mime-info fonts-dejavu-core \
      # scanners
      nmap whatweb \
      # build + fetch tooling
      curl ca-certificates gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# --- nuclei ------------------------------------------------------------------
# Installed from the official release archive; the templates are fetched on
# first run. If this layer fails the platform still works — the Nuclei adapter
# simply reports itself as unavailable and is skipped.
ARG NUCLEI_VERSION=3.3.7
ARG TARGETARCH=amd64
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    && cd /tmp && (unzip -o nuclei.zip nuclei -d /usr/local/bin || apt-get update \
       && apt-get install -y --no-install-recommends unzip \
       && unzip -o nuclei.zip nuclei -d /usr/local/bin) \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    || echo "Nuclei install skipped — the adapter will report itself unavailable."

# --- python dependencies -----------------------------------------------------
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# --- application -------------------------------------------------------------
COPY . .

# Run as an unprivileged user. Nmap runs only TCP connect scans, which need no
# elevated capabilities.
RUN useradd --create-home --shell /bin/bash prcampus \
    && mkdir -p /app/storage \
    && chown -R prcampus:prcampus /app
USER prcampus

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
