# Docker Testing Guide for the ModSecurity Apache Connector

A smoke-test harness for the ModSecurity v3 Apache connector. It builds
libmodsecurity and the connector from source, loads a two-rule test set, and
lets connector behaviour be observed directly. It is not a production
configuration.

## Quick Start

```bash
docker compose up -d --build
./test-connector.sh
```

Compose is the supported way to run this: the tests read the ModSecurity debug
log through the bind mount it sets up, so a bare `docker run` will not work.

## Manual Testing

```bash
# Normal request (200)
curl http://localhost:8080/

# Query string rule, id 1001 (403)
curl -v "http://localhost:8080/?test=evil"

# Request body rule, id 1002 (403)
curl -X POST http://localhost:8080/ -d "data=malicious"

# Large body, no match (200)
curl -X POST http://localhost:8080/ -d "$(head -c 100000 /dev/zero | tr '\0' 'A')"

# Large body spanning multiple buckets, with a match at the end (403)
curl -X POST http://localhost:8080/ -d "$(head -c 100000 /dev/zero | tr '\0' 'A')malicious"
```

Bodies stay under the 128KB `SecRequestBodyNoFilesLimit` from the recommended
configuration; larger ones are rejected with 413 before the rules run. A 10KB
body arrives in a single bucket, so it does not exercise multi-bucket handling.

## Observing rule evaluation

Denied requests are **not** written to the Apache error log — that is upstream
issue #67, not a misconfiguration here. Two other signals are available:

- `logs/modsec_audit.log` — one entry per transaction, showing which rule
  matched. It does not tell you how many times a rule was evaluated.
- `logs/modsec_debug.log` — one line per phase invocation. This is the only
  signal that shows how often a phase actually ran.

`test-connector.sh` uses the debug log to report how many times the
request-body phase ran for a single large POST:

```
request-body phase invocations for that request: 26 (KNOWN BUG: expected 1, ...)
```

A correct connector assembles the whole body and evaluates it once. The
current source re-runs the phase for every bucket, which is the defect behind
the request-body work; the count is reported rather than asserted so this
branch stays green. Once the fix lands it becomes a hard assertion.

## Debugging

```bash
# Live logs
docker compose logs -f

# Shell into the container
docker compose exec modsec3-apache bash

# Confirm the module loaded
apache2ctl -M | grep security3

# Module dependencies
ldd /usr/lib/apache2/modules/mod_security3.so

# Active configuration
cat /etc/modsecurity/modsecurity.conf
cat /etc/modsecurity/test-rules.conf
```

## Expected Results

All 6 checks in `test-connector.sh` pass:

1. Normal request — 200
2. Query string block — 403
3. Request body block — 403
4. Normal POST — 200
5. Large POST — 200
6. Large POST with a match — 403

Test 6 additionally reports the request-body phase count described above.

## What's Included

- **libmodsecurity** v3.0.16, built from the pinned release tag
- **Apache HTTP Server** 2.4.68, from Debian bookworm
- **ModSecurity Apache Connector**, built from this working tree

The recommended ModSecurity configuration is copied out of the same
libmodsecurity source tree that was built, so it cannot drift from the
version in the image.

## See also

- Valgrind memcheck + helgrind soak of the running module, including
  periodic graceful restarts (the operation issue #82 reports leaking
  memory): `tools/soak.sh`, built via `Dockerfile.fuzz`.
