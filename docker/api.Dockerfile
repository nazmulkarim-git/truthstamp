FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libimage-exiftool-perl \
    ca-certificates \
    curl \
    tar \
  && rm -rf /var/lib/apt/lists/*

# Install c2patool (prebuilt Linux binary from contentauth/c2pa-rs).
ARG C2PATOOL_VERSION=0.26.8
RUN curl -L -o /tmp/c2patool.tgz \
    https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v${C2PATOOL_VERSION}/c2patool-v${C2PATOOL_VERSION}-x86_64-unknown-linux-gnu.tar.gz \
  && tar -xzf /tmp/c2patool.tgz -C /tmp \
  && ( \
       if [ -f /tmp/c2patool ]; then SRC=/tmp/c2patool; \
       else SRC=$(find /tmp -maxdepth 3 -type f -name c2patool | head -n 1); fi; \
       echo "Using c2patool binary at: $SRC"; \
       install -m 0755 "$SRC" /usr/local/bin/c2patool; \
     ) \
  && rm -f /tmp/c2patool.tgz \
  && /usr/local/bin/c2patool --version || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
RUN mkdir -p /app/data

CMD ["sh", "-lc", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
