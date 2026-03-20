FROM python:3.12-slim

LABEL maintainer="DAST Framework Contributors"
LABEL description="DAST Framework — Dynamic Application Security Testing for injection vulnerabilities"

# System dependencies:
#   curl        — health checks and target reachability test in entrypoint.sh
#   iptables    — minimal firewall in entrypoint.sh
#   xxd         — scan_id generation in entrypoint.sh
#   libxml2-dev / libxslt-dev — required by lxml (Python BeautifulSoup backend)
#   gcc         — needed to compile some Python C extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        iptables \
        xxd \
        libxml2-dev \
        libxslt-dev \
        gcc \
        libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (separate layer for Docker cache efficiency).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers to a shared path accessible by all users.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install-deps chromium \
    && playwright install chromium \
    && chmod -R 755 /ms-playwright

# Copy application source code.
COPY src/       ./src/
COPY payloads/  ./payloads/
COPY config/    ./config/
COPY templates/ ./templates/
COPY pyproject.toml .

# Copy and set permissions for the entrypoint script.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create the reports output directory.
RUN mkdir -p /app/reports

# Run as a non-root user where possible.
# NET_ADMIN capability is still required for iptables (granted via docker-compose).
RUN useradd --create-home --shell /bin/bash dastuser \
    && chown -R dastuser:dastuser /app
USER dastuser

ENTRYPOINT ["/entrypoint.sh"]
