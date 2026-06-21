FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    # Network recon
    nmap masscan netcat-traditional dnsutils whois curl wget \
    # Web assessment
    nikto gobuster sqlmap \
    # OSINT
    theharvester recon-ng \
    # Password / hash
    john hydra \
    # Utilities
    python3 python3-pip jq git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python-based tools not in apt
RUN pip3 install --no-cache-dir \
    shodan \
    censys \
    requests \
    dnspython \
    python-whois

# nuclei (Go binary)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -update-templates -silent || true

WORKDIR /workspaces

# Keep container alive; Odysseus MCP servers exec into it
CMD ["tail", "-f", "/dev/null"]
