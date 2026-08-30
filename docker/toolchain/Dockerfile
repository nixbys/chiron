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
    # Needed to build yara-python below from source when Kali Rolling's
    # current Python has no matching prebuilt wheel on PyPI (pip then falls
    # back to compiling, which needs a C compiler and the Python headers).
    build-essential python3-dev \
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
    yara-python

# ── Go-based security tools (ProjectDiscovery suite + Amass) ──────────────────
# Each tool is installed independently with retries. A single download failure
# does not abort the image build — the tool is simply skipped. Verify presence
# with `docker run odysseus-toolchain which nuclei` before production use.
#
# ProjectDiscovery's tools (nuclei/httpx/subfinder) and trivy embed the
# version number in their release asset filenames (e.g.
# `nuclei_3.11.1_linux_amd64.zip`, not `nuclei_linux_amd64.zip`), so the old
# fixed-filename `.../releases/latest/download/<name>_linux_amd64.zip` URLs
# 404 unconditionally once a version ships under that convention — GitHub's
# "latest/download" alias only rewrites the *release*, not the asset name.
# `_gh_latest_tag` resolves the actual tag first so the filename it builds
# always matches what that release really published.
RUN _gh_latest_tag() { \
        curl --retry 3 --retry-delay 5 -fsSL "https://api.github.com/repos/$1/releases/latest" \
            | jq -r '.tag_name'; \
    } && \
    _install_zip() { \
        name="$1"; url="$2"; bin="$3"; \
        curl --retry 3 --retry-delay 5 -fsSL "$url" -o "/tmp/${name}.zip" 2>/dev/null \
        && unzip -q "/tmp/${name}.zip" "$bin" -d /usr/local/bin/ \
        && chmod +x "/usr/local/bin/$bin" \
        && rm -f "/tmp/${name}.zip" \
        && echo "Installed $bin" \
        || { echo "WARNING: failed to install $bin — skipping"; rm -f "/tmp/${name}.zip"; }; \
    } && \
    nuclei_tag="$(_gh_latest_tag projectdiscovery/nuclei)" && \
    _install_zip nuclei \
        "https://github.com/projectdiscovery/nuclei/releases/download/${nuclei_tag}/nuclei_${nuclei_tag#v}_linux_amd64.zip" \
        nuclei && \
    (which nuclei && nuclei -update-templates -silent 2>/dev/null || true) && \
    httpx_tag="$(_gh_latest_tag projectdiscovery/httpx)" && \
    _install_zip httpx \
        "https://github.com/projectdiscovery/httpx/releases/download/${httpx_tag}/httpx_${httpx_tag#v}_linux_amd64.zip" \
        httpx && \
    subfinder_tag="$(_gh_latest_tag projectdiscovery/subfinder)" && \
    _install_zip subfinder \
        "https://github.com/projectdiscovery/subfinder/releases/download/${subfinder_tag}/subfinder_${subfinder_tag#v}_linux_amd64.zip" \
        subfinder && \
    # amass's asset filename carries no version (unlike the three above) --
    # only its case (lowercase "linux", not "Linux") and extension (.tar.gz,
    # not .zip) were wrong. Binary sits inside a versioned subdirectory in
    # the tarball, so extract-and-find rather than a flat unzip.
    ( curl --retry 3 --retry-delay 5 -fsSL \
        "https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.tar.gz" \
        -o /tmp/amass.tar.gz 2>/dev/null \
      && mkdir -p /tmp/amass_out && tar -xzf /tmp/amass.tar.gz -C /tmp/amass_out/ \
      && find /tmp/amass_out/ -name amass -type f -exec mv {} /usr/local/bin/amass \; \
      && chmod +x /usr/local/bin/amass \
      && echo "Installed amass" \
      || echo "WARNING: failed to install amass — skipping" \
    ) && rm -rf /tmp/amass.tar.gz /tmp/amass_out/ && \
    # trivy — container/filesystem vulnerability scanner (also versioned,
    # and "Linux-64bit" rather than "linux_amd64")
    trivy_tag="$(_gh_latest_tag aquasecurity/trivy)" && \
    ( curl --retry 3 --retry-delay 5 -fsSL \
        "https://github.com/aquasecurity/trivy/releases/download/${trivy_tag}/trivy_${trivy_tag#v}_Linux-64bit.tar.gz" \
        | tar -xz -C /usr/local/bin/ trivy \
      && chmod +x /usr/local/bin/trivy \
      && echo "Installed trivy" \
      || echo "WARNING: failed to install trivy — skipping" \
    )

# ── Exec API — MCP servers call this instead of podman exec ───────────────────
COPY exec_api.py /exec_api.py

# ── Default directories ────────────────────────────────────────────────────────
RUN mkdir -p /workspaces /reports /workspaces/yara_rules

WORKDIR /workspaces

# Health check: verify exec API is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["sh", "-c", "curl -sf http://localhost:8088/health || exit 1"]

# The exec API keeps the container alive and handles all tool invocations
# from the MCP servers running inside the Odysseus container.
CMD ["python3", "/exec_api.py"]
