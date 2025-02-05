FROM python:3.11-slim

ENV PATH="/root/go/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    git \
    curl \
    unzip \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin

ENV GO_VERSION=1.21.0
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest && \
	go install -v github.com/projectdiscovery/katana/cmd/katana@latest

RUN pip install --no-cache-dir requests postleaks uro

WORKDIR /app

RUN git clone https://github.com/Van-1337/EASM-automate.git .

RUN chmod +x Scan/byp4xx.go

RUN mkdir -p /app/output

ENTRYPOINT ["python", "main.py", "--docker"]

CMD []