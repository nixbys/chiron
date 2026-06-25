# kali-rolling:latest is the only reliably published tag on Docker Hub.
# For a fully reproducible build, pin by digest:
#   docker pull kalilinux/kali-rolling:latest
#   docker inspect kalilinux/kali-rolling:latest --format '{{index .RepoDigests 0}}'
# Then replace `latest` below with `kalilinux/kali-rolling@sha256:<digest>`.
FROM docker.io/kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    # Network recon
    nmap masscan netcat-traditional dnsutils whois curl wget \
    # Web assessment
    nikto gobuster sqlmap \
    # Web fuzzing
    ffuf \
    # OSINT
    theharvester recon-ng \
    # Password / hash
    john hydra \
    # Exploitation
    exploitdb \
    metasploit-framework \
    # Forensics & analysis
    binwalk exiftool \
    yara \
    # Wordlists
    wordlists \
    # Utilities
    python3 python3-pip jq git ca-certificates unzip p7zip-full \
    # Runtime deps for amass/subfinder/httpx
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# ── Python-based tools ──────────────────────────────────────────────────────────
# --break-system-packages: Kali Rolling enforces PEP 668; safe inside a container.
RUN pip3 install --no-cache-dir --break-system-packages \
    shodan \
    censys \
    requests \
    dnspython \
    python-whois \
    hashid \
    sherlock-project \
    yara-python \
    semgrep

# ── Go-based security tools (ProjectDiscovery suite + Amass) ──────────────────
RUN set -e && \
    # nuclei — template-based vulnerability scanner
    curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
        -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent 2>/dev/null || true && \
    # httpx — fast HTTP probing and banner grabbing
    curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip \
        -o /tmp/httpx.zip && \
    unzip -q /tmp/httpx.zip httpx -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && rm /tmp/httpx.zip && \
    # subfinder — fast passive subdomain enumeration
    curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip \
        -o /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip && \
    # amass — comprehensive subdomain enumeration and attack surface mapping
    curl -sL https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip \
        -o /tmp/amass.zip && \
    unzip -q /tmp/amass.zip -d /tmp/amass_out/ && \
    find /tmp/amass_out/ -name amass -type f -exec mv {} /usr/local/bin/amass \; && \
    chmod +x /usr/local/bin/amass && rm -rf /tmp/amass.zip /tmp/amass_out/ && \
    # trivy — container/filesystem vulnerability scanner
    curl -sL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_linux_amd64.tar.gz \
        | tar -xz -C /usr/local/bin/ trivy && \
    chmod +x /usr/local/bin/trivy

# ── Exec API — MCP servers call this instead of podman exec ───────────────────
COPY exec_api.py /exec_api.py

# ── Default directories ────────────────────────────────────────────────────────
RUN mkdir -p /workspaces /reports /workspaces/yara_rules

WORKDIR /workspaces

# Health check: verify exec API is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8088/health || exit 1

# The exec API keeps the container alive and handles all tool invocations
# from the MCP servers running inside the Odysseus container.
CMD ["python3", "/exec_api.py"]
