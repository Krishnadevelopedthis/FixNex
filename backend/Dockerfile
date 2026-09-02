# ============================================================================
# FixNex Backend
#
# Multi-purpose production image:
#   1. FastAPI API/Web Service
#   2. Celery Background Worker
#
# Includes:
#   - Python 3.11
#   - PostgreSQL dependencies
#   - WeasyPrint dependencies
#   - Nmap
#   - WhatWeb
#   - Nuclei
#
# The same Docker image is used by:
#
#   Render Web Service
#       -> Uvicorn / FastAPI
#
#   Render Background Worker
#       -> Celery
# ============================================================================


# ----------------------------------------------------------------------------
# Base image
# ----------------------------------------------------------------------------

FROM python:3.11-slim


# ----------------------------------------------------------------------------
# Python environment
# ----------------------------------------------------------------------------

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app


# ----------------------------------------------------------------------------
# Application directory
# ----------------------------------------------------------------------------

WORKDIR /app


# ----------------------------------------------------------------------------
# System dependencies
#
# WeasyPrint:
#   - Pango
#   - Cairo
#   - GDK Pixbuf
#   - libffi
#   - shared-mime-info
#   - fonts
#
# Security scanners:
#   - Nmap
#   - WhatWeb
#
# Build/database/network:
#   - curl
#   - ca-certificates
#   - unzip
#   - gcc
#   - libpq-dev
# ----------------------------------------------------------------------------

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
        fonts-dejavu-core \
        nmap \
        whatweb \
        curl \
        ca-certificates \
        unzip \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*


# ----------------------------------------------------------------------------
# Install Nuclei
#
# ProjectDiscovery Nuclei official release.
#
# Docker BuildKit supplies TARGETARCH automatically, but amd64 is used as
# the default for Render's normal x86_64 infrastructure.
# ----------------------------------------------------------------------------

ARG NUCLEI_VERSION=3.3.7
ARG TARGETARCH=amd64

RUN set -eux; \
    curl -fsSL \
        -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f /tmp/nuclei.zip; \
    nuclei -version


# ----------------------------------------------------------------------------
# Install Python dependencies
# ----------------------------------------------------------------------------

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt


# ----------------------------------------------------------------------------
# Copy application
# ----------------------------------------------------------------------------

COPY . /app


# ----------------------------------------------------------------------------
# Create non-root application user
#
# Security scanners are executed without root privileges.
#
# Nmap should use TCP connect scans rather than privileged raw-packet scans.
# ----------------------------------------------------------------------------

RUN useradd \
        --create-home \
        --shell /bin/bash \
        --uid 10001 \
        prcampus \
    && mkdir -p /app/storage \
    && mkdir -p /home/prcampus/.config \
    && mkdir -p /home/prcampus/.cache \
    && chown -R prcampus:prcampus /app \
    && chown -R prcampus:prcampus /home/prcampus


# ----------------------------------------------------------------------------
# Runtime environment
# ----------------------------------------------------------------------------

ENV HOME=/home/prcampus \
    PATH=/usr/local/bin:/usr/bin:/bin

USER prcampus


# ----------------------------------------------------------------------------
# FastAPI port
#
# Used by the Render Web Service.
#
# The Celery worker does not need to listen on this port.
# ----------------------------------------------------------------------------

EXPOSE 8000


# ----------------------------------------------------------------------------
# Default command
#
# Render Web Service:
#   Uses this command automatically.
#
# Render Background Worker:
#   Overrides this command with the Celery worker command.
# ----------------------------------------------------------------------------

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
