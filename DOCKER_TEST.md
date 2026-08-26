# Docker Testing Guide for ModSecurity Apache Connector

This Docker setup tests the ModSecurity v3 Apache connector with all implemented fixes.

## Quick Start

```bash
# Build and run
docker build -t modsec3-apache-test .
docker run -d -p 8080:8080 --name modsec3-test modsec3-apache-test

# Or use docker-compose
docker-compose up -d

# Run automated tests
./test-connector.sh
```

## Manual Testing

```bash
# Test 1: Normal request (should work - 200 OK)
curl http://localhost:8080/

# Test 2: Query string rule (should be blocked - 403 Forbidden)
curl -v http://localhost:8080/?test=evil

# Test 3: Request body rule (should be blocked - 403 Forbidden)
curl -X POST http://localhost:8080/ -d "data=malicious"

# Test 4: Large POST - tests multi-bucket processing (should work - 200 OK)
curl -X POST http://localhost:8080/ -d "$(head -c 20000 /dev/zero | tr '\0' 'A')"

# Test 5: Large POST with evil content (should be blocked - 403)
# This specifically verifies the request body processing fix!
curl -X POST http://localhost:8080/ -d "A$(head -c 15000 /dev/zero | tr '\0' 'A')malicious"
```

## Verifying the Fixes

### ✅ Fix #1: Request Body Processing
**Issue**: Rules fired multiple times (once per ~8KB bucket)
**Fix**: Only call `msc_process_request_body()` once at EOS

**Test**:
```bash
# Send large POST with "malicious" at the end
curl -v -X POST http://localhost:8080/ -d "$(head -c 20000 /dev/zero | tr '\0' 'A')malicious"
```
**Expected**: HTTP 403 (proves rules evaluated the complete body correctly)

### ✅ Fix #2: Status Code Control
**Issue**: ModSecurity couldn't set status codes (missing `r->status`)
**Fix**: Added `f->r->status = status;` before `status_line`

**Test**:
```bash
curl -v http://localhost:8080/?test=evil
```
**Expected**: `HTTP/1.1 403 Forbidden` (not 400 or other)

### ✅ Fix #3: Filter Removal
**Issue**: Input filter called `ap_remove_output_filter()`
**Fix**: Changed to `ap_remove_input_filter()`

**Test**: Run all tests - no crashes

### ✅ Fix #4: Error Handling
**Issue**: `apr_bucket_read()` return value not checked
**Fix**: Added error checking

**Test**: Normal operation should work without errors

## Debugging

```bash
# View live logs
docker logs -f modsec3-test

# Enter container
docker exec -it modsec3-test bash

# Check module loaded
/usr/local/apache2/bin/apachectl -M | grep security3

# Check module dependencies
ldd /usr/local/apache2/modules/mod_security3.so

# View ModSecurity config
cat /etc/modsecurity/modsecurity.conf
cat /etc/modsecurity/test-rules.conf
```

## Expected Results

All 6 tests should pass:
1. ✅ Normal request - 200 OK
2. ✅ Query string block - 403 Forbidden
3. ✅ Request body block - 403 Forbidden
4. ✅ Normal POST - 200 OK
5. ✅ Large POST (multi-bucket) - 200 OK
6. ✅ Large POST with evil - 403 Forbidden (verifies the fix!)

## What's Included

- **libmodsecurity v3** (latest from v3/master branch)
- **Apache HTTP Server 2.4.62**
- **ModSecurity Apache Connector** with fixes:
  - Request body processing (process once at EOS)
  - Status code control (r->status properly set)
  - Filter removal (correct function called)
  - Error handling (return values checked)

## What this environment is for

The image builds libmodsecurity and the connector from source and runs a small
rule set, so connector behaviour can be observed directly. It is a smoke-test
harness, not a production configuration.

Rule evaluation is visible in `logs/modsec_debug.log`; denied requests do not
appear in the Apache error log (upstream issue #67), and `logs/modsec_audit.log`
records one entry per transaction rather than one per rule evaluation.
