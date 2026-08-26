# Dockerfile for testing the ModSecurity v3 Apache connector.
# Builds libmodsecurity3 and the connector against Debian's Apache.

FROM debian:bookworm-slim AS builder

ARG MODSECURITY_VERSION=v3.0.16

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Build essentials
        build-essential \
        ca-certificates \
        automake \
        autoconf \
        libtool \
        pkg-config \
        git \
        # Apache module build support (apxs2, plus the httpd binary configure probes for)
        apache2 \
        apache2-dev \
        # libmodsecurity dependencies
        libcurl4-openssl-dev \
        libyajl-dev \
        libgeoip-dev \
        liblmdb-dev \
        libxml2-dev \
        libpcre2-dev \
        libmaxminddb-dev \
        libfuzzy-dev && \
    rm -rf /var/lib/apt/lists/*

# Build libmodsecurity v3 from a pinned release tag
WORKDIR /build

RUN git clone --depth 1 --branch ${MODSECURITY_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity.git libmodsecurity && \
    cd libmodsecurity && \
    git submodule update --init --recursive && \
    ./build.sh && \
    ./configure \
        --prefix=/usr/local/modsecurity \
        --with-pcre2 \
        --with-yajl \
        --with-geoip \
        --with-lmdb && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build the connector; configure finds Debian's apxs2 on its own
WORKDIR /build/connector

COPY . .

RUN ./autogen.sh && \
    ./configure --with-libmodsecurity=/usr/local/modsecurity && \
    make -j$(nproc) && \
    make install

FROM debian:bookworm-slim

LABEL description="Apache with the ModSecurity v3 connector, for smoke testing"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2 \
        wget \
        libcurl4 \
        libyajl2 \
        libgeoip1 \
        liblmdb0 \
        libxml2 \
        libpcre2-8-0 \
        libmaxminddb0 \
        libfuzzy2 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=builder /usr/lib/apache2/modules/mod_security3.so /usr/lib/apache2/modules/

RUN echo "/usr/local/modsecurity/lib" > /etc/ld.so.conf.d/modsecurity.conf && \
    ldconfig

# Take the recommended config from the same source tree we built, so it can
# never drift from the pinned libmodsecurity version.
COPY --from=builder /build/libmodsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
COPY --from=builder /build/libmodsecurity/unicode.mapping /etc/modsecurity/unicode.mapping

RUN sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

RUN cat > /etc/modsecurity/test-rules.conf << 'EOF'
# Fires on the query string, to check phase 1 / ARGS handling
SecRule ARGS:test "@contains evil" \
    "id:1001,phase:2,deny,status:403,msg:'Test rule triggered'"

# Fires on the request body, to check that a multi-bucket body is assembled
# and evaluated exactly once
SecRule REQUEST_BODY "@rx malicious" \
    "id:1002,phase:2,deny,status:403,msg:'Request body rule triggered'"

# The connector does not write denied requests to the Apache error log
# (upstream issue #67), and the audit log records one entry per transaction
# rather than one per rule evaluation. The debug log is the only signal that
# shows how many times a phase actually ran, which is what the request-body
# tests need to check.
SecDebugLog /var/log/apache2/modsec_debug.log
SecDebugLogLevel 4
SecAuditLog /var/log/apache2/modsec_audit.log
EOF

RUN cat > /etc/apache2/mods-available/security3.load << 'EOF'
LoadModule security3_module /usr/lib/apache2/modules/mod_security3.so

<IfModule security3_module>
    modsecurity on
    modsecurity_rules_file /etc/modsecurity/modsecurity.conf
    modsecurity_rules_file /etc/modsecurity/test-rules.conf
</IfModule>
EOF

RUN a2enmod security3 && \
    sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf && \
    sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' \
        /etc/apache2/sites-available/000-default.conf && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

RUN cat > /usr/local/bin/start.sh << 'EOF'
#!/bin/bash
set -e

if ! apache2ctl -M 2>&1 | grep -q security3_module; then
    echo "ERROR: ModSecurity module not loaded!"
    ldd /usr/lib/apache2/modules/mod_security3.so
    exit 1
fi

echo "ModSecurity module loaded, starting Apache on :8080"
exec apache2ctl -DFOREGROUND
EOF

RUN chmod +x /usr/local/bin/start.sh

EXPOSE 8080

CMD ["/usr/local/bin/start.sh"]
