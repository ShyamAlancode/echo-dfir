FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update -qq && apt-get install -y -qq \
    python3 python3-pip python3-venv \
    bulk-extractor \
    libparse-win32registry-perl \
    git curl unzip \
    && rm -rf /var/lib/apt/lists/*

# RegRipper
RUN git clone --quiet --depth 1 \
        https://github.com/keydet89/RegRipper3.0 /opt/regripper && \
    ln -sf /opt/regripper/rip.pl /usr/local/bin/rip.pl && \
    chmod +x /opt/regripper/rip.pl

WORKDIR /app
COPY pyproject.toml ./
COPY echo_mcp ./echo_mcp
COPY echo_agent ./echo_agent
COPY validators ./validators
COPY tests ./tests
COPY pytest.ini ./
COPY README.md LICENSE ./

RUN pip install --quiet --break-system-packages -e .

# Volatility 3 + symbol pack
RUN pip install --quiet --break-system-packages 'volatility3>=2.7' && \
    mkdir -p /root/.cache/volatility3/symbols/windows && \
    curl -fsSL https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip \
        -o /tmp/win.zip && \
    (cd /root/.cache/volatility3/symbols/windows && unzip -q /tmp/win.zip) && \
    rm /tmp/win.zip

RUN mkdir -p /app/audit /app/findings /mnt/cases

ENTRYPOINT ["echo"]
CMD ["--help"]
