# Dockerfile for testing ModSecurity v3 Apache Connector with fixes
# Multi-stage build: libmodsecurity3, Apache, and the connector

FROM debian:bookworm-slim AS builder

# Install build dependencies
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
        wget \
        # Apache build dependencies
        libapr1-dev \
        libaprutil1-dev \
        libpcre2-dev \
        libssl-dev \
        zlib1g-dev \
        # libmodsecurity dependencies
        libcurl4-openssl-dev \
        libyajl-dev \
        libgeoip-dev \
        liblmdb-dev \
        libxml2-dev \
        libpcre3-dev \
        libmaxminddb-dev \
        libfuzzy-dev && \
    rm -rf /var/lib/apt/lists/*

# Stage 1: Build libmodsecurity v3
WORKDIR /build

RUN git clone --depth 1 --branch v3/master \
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

# Stage 2: Build Apache HTTP Server
WORKDIR /build

ARG APACHE_VERSION=2.4.62

RUN wget -O httpd.tar.gz \
        https://archive.apache.org/dist/httpd/httpd-${APACHE_VERSION}.tar.gz && \
    tar -xzf httpd.tar.gz && \
    cd httpd-${APACHE_VERSION} && \
    ./configure \
        --prefix=/usr/local/apache2 \
        --enable-mods-shared=all \
        --enable-mpms-shared="prefork worker event" \
        --enable-so \
        --enable-rewrite \
        --enable-ssl \
        --enable-proxy \
        --enable-proxy-http \
        --with-mpm=event && \
    make -j$(nproc) && \
    make install

# Stage 3: Build ModSecurity Apache Connector (with our fixes)
WORKDIR /build/connector

# Copy the fixed connector code
COPY . .

RUN ./autogen.sh && \
    ./configure \
        --with-apxs=/usr/local/apache2/bin/apxs \
        --with-libmodsecurity=/usr/local/modsecurity && \
    make -j$(nproc) && \
    make install

# Stage 4: Create runtime image
FROM debian:bookworm-slim

LABEL maintainer="ModSecurity Apache Connector Test"
LABEL description="Apache with ModSecurity v3 connector (with fixes)"

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        libcurl4 \
        libyajl2 \
        libgeoip1 \
        liblmdb0 \
        libxml2 \
        libpcre3 \
        libmaxminddb0 \
        libfuzzy2 \
        libapr1 \
        libaprutil1 \
        libaprutil1-dbd-sqlite3 \
        libaprutil1-ldap && \
    rm -rf /var/lib/apt/lists/*

# Copy libmodsecurity from builder
COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity

# Copy Apache from builder
COPY --from=builder /usr/local/apache2 /usr/local/apache2

# Update library cache
RUN echo "/usr/local/modsecurity/lib" > /etc/ld.so.conf.d/modsecurity.conf && \
    ldconfig

# Create necessary directories
RUN mkdir -p \
        /var/log/apache2 \
        /var/log/modsecurity/audit \
        /tmp/modsecurity/data \
        /tmp/modsecurity/tmp \
        /tmp/modsecurity/upload \
        /etc/modsecurity && \
    chown -R www-data:www-data \
        /var/log/apache2 \
        /var/log/modsecurity \
        /tmp/modsecurity

# Download recommended ModSecurity configuration
WORKDIR /etc/modsecurity

RUN wget -O modsecurity.conf \
        https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended && \
    wget -O unicode.mapping \
        https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping && \
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' modsecurity.conf

# Create a simple test configuration
RUN cat > /etc/modsecurity/test-rules.conf << 'EOF'
# Test rule to verify ModSecurity is working
SecRule ARGS:test "@contains evil" \
    "id:1001,phase:2,deny,status:403,msg:'Test rule triggered'"

# Test rule for request body
SecRule REQUEST_BODY "@rx malicious" \
    "id:1002,phase:2,deny,status:403,msg:'Request body rule triggered'"
EOF

# Configure Apache with ModSecurity
RUN cat > /usr/local/apache2/conf/extra/modsecurity.conf << 'EOF'
# Load ModSecurity module
LoadModule security3_module modules/mod_security3.so

# ModSecurity configuration
<IfModule security3_module>
    # Enable ModSecurity
    modsecurity on

    # Load base configuration
    modsecurity_rules_file /etc/modsecurity/modsecurity.conf

    # Load test rules
    modsecurity_rules_file /etc/modsecurity/test-rules.conf
</IfModule>
EOF

# Update main Apache configuration
RUN sed -i \
        -e 's/^Listen 80$/Listen 8080/' \
        -e '/^#Include conf\/extra\/httpd-mpm.conf/s/^#//' \
        /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/modsecurity.conf" >> /usr/local/apache2/conf/httpd.conf && \
    echo "ServerName localhost" >> /usr/local/apache2/conf/httpd.conf

# Create a simple test page
RUN mkdir -p /usr/local/apache2/htdocs/test && \
    cat > /usr/local/apache2/htdocs/test/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>ModSecurity Test</title></head>
<body>
    <h1>ModSecurity v3 Apache Connector Test</h1>
    <p>If you see this page, Apache is working!</p>

    <h2>Test Cases:</h2>
    <ul>
        <li>Normal request: <a href="/">Should work</a></li>
        <li>Trigger test rule: <a href="/?test=evil">Should be blocked (403)</a></li>
        <li>POST with evil body: Use curl to test request body processing</li>
    </ul>

    <h2>Test Commands:</h2>
    <pre>
# Test normal request
curl http://localhost:8080/

# Test query string rule (should return 403)
curl http://localhost:8080/?test=evil

# Test request body rule (should return 403)
curl -X POST http://localhost:8080/ -d "data=malicious"

# Test large POST (tests bucket processing fix)
curl -X POST http://localhost:8080/ -d "$(head -c 10000 /dev/urandom | base64)"
    </pre>
</body>
</html>
EOF

# Create startup script
RUN cat > /usr/local/bin/start.sh << 'EOF'
#!/bin/bash
set -e

echo "Starting Apache with ModSecurity v3..."
echo ""
echo "Configuration:"
echo "  Apache: /usr/local/apache2"
echo "  ModSecurity lib: /usr/local/modsecurity"
echo "  Rules: /etc/modsecurity/"
echo "  Logs: /var/log/apache2/"
echo ""
echo "Test the connector:"
echo "  curl http://localhost:8080/"
echo "  curl http://localhost:8080/?test=evil  # Should be blocked"
echo ""

# Check if ModSecurity module loads
if ! /usr/local/apache2/bin/apachectl -M 2>&1 | grep -q security3_module; then
    echo "ERROR: ModSecurity module not loaded!"
    echo "Checking module:"
    ls -la /usr/local/apache2/modules/mod_security3.so
    echo ""
    echo "Checking dependencies:"
    ldd /usr/local/apache2/modules/mod_security3.so
    exit 1
fi

echo "ModSecurity module loaded successfully!"
echo ""

# Start Apache in foreground
exec /usr/local/apache2/bin/httpd -DFOREGROUND
EOF

RUN chmod +x /usr/local/bin/start.sh

EXPOSE 8080

CMD ["/usr/local/bin/start.sh"]
