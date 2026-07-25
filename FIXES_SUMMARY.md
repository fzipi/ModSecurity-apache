# ModSecurity Apache Connector - Fixes Summary

## Overview
This document summarizes the fixes applied to make the ModSecurity v3 Apache connector functional and production-ready.

## Test Results
**All 6 tests passing (100%)**
- ✅ Normal request handling
- ✅ Query string rule blocking (HTTP 403)
- ✅ Request body rule blocking (HTTP 403)
- ✅ Normal POST requests
- ✅ Large POST requests (multi-bucket handling)
- ✅ Large POST with malicious content detection

## Critical Fixes Implemented

### 1. Request Body Processing Fix
**Files:** `src/msc_filters.c`, `src/mod_security3.c`, `src/mod_security3.h`

**Problem:** Rules were firing multiple times (once per ~8KB bucket) instead of once after complete body was received.

**Solution:**
- Added `request_body_processed` flag to track buffering state
- Input filter now only buffers body data using `msc_append_request_body()`
- Processing moved to handler phase where it's called once with complete body
- Prevents duplicate rule evaluations and ensures full body inspection

**Code Changes:**
```c
// mod_security3.h - Added flag
typedef struct {
    request_rec *r;
    Transaction *t;
    int request_body_processed;  // NEW
} msc_t;

// msc_filters.c - Buffer only, don't process
if (APR_BUCKET_IS_EOS(pbktIn)) {
    msr->request_body_processed = 1;  // Mark complete
    // Processing happens in handler, not here
}
msc_append_request_body(msr->t, data, len);  // Buffer chunks

// mod_security3.c - Process in handler phase
ap_hook_handler(hook_request_late, NULL, NULL, APR_HOOK_REALLY_FIRST);
```

### 2. HTTP Status Code Control Fix
**File:** `src/msc_utils.c`

**Problem:** ModSecurity couldn't set HTTP status codes - interventions returned 400 instead of configured status (e.g., 403).

**Root Cause:** Code only set `r->status_line` but not `r->status`.

**Solution:**
```c
// OLD CODE:
f->r->status_line = ap_get_status_line(status);

// FIXED CODE:
f->r->status = status;                        // ← ADDED THIS
f->r->status_line = ap_get_status_line(status);
```

### 3. Apache Hook Phase Fix
**File:** `src/mod_security3.c`

**Problem:** Request body reading attempted in `fixups` hook, but Apache requires body reading in `handler` phase.

**Solution:** Changed from `ap_hook_fixups` to `ap_hook_handler`:
```c
// OLD: ap_hook_fixups(hook_request_late, ...)
// NEW: ap_hook_handler(hook_request_late, ...)
```

**Critical Insight:** Learned from analyzing other Apache modules (mod_proxy_scgi, etc.) - they all read request bodies in handler phase, not fixups.

### 4. Filter Removal Bug Fix
**File:** `src/msc_filters.c`

**Problem:** Input filter called `ap_remove_output_filter()` instead of `ap_remove_input_filter()`.

**Solution:**
```c
// OLD: ap_remove_output_filter(f);
// NEW: ap_remove_input_filter(f);
```

### 5. Error Handling Enhancement
**File:** `src/msc_filters.c`

**Problem:** Return value of `apr_bucket_read()` was not checked.

**Solution:** Added error checking:
```c
apr_status_t rv;
rv = apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, f->r->server,
        "ModSecurity: Error reading response body bucket");
    return rv;
}
```

### 6. Context Creation Timing Fix
**File:** `src/mod_security3.c`

**Problem:** `hook_insert_filter` expected context to exist but it wasn't created yet.

**Solution:** Create context in `hook_insert_filter` if it doesn't exist:
```c
msr = retrieve_tx_context(r);
if (msr == NULL) {
    msr = create_tx_context(r);  // Create if needed
    if (msr == NULL) return;
}
```

### 7. Request Body Reading Implementation
**File:** `src/mod_security3.c`

**Problem:** Apache doesn't automatically read request bodies - modules must explicitly request them.

**Solution:** Added proper body reading in handler:
```c
int rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
if (rc != OK) return rc;

if (ap_should_client_block(r)) {
    char buffer[HUGE_STRING_LEN];
    apr_off_t len;
    while ((len = ap_get_client_block(r, buffer, sizeof(buffer))) > 0) {
        // Input filter intercepts and buffers to ModSecurity
    }
}

msc_process_request_body(msr->t);  // Process after complete read
```

## Architecture Understanding

### Apache Filter Chain vs Hook Phases
- **Input Filters:** Passive - only run when someone reads the request body
- **Hooks:** Active - run at specific phases of request processing
- **Key Insight:** Body reading must happen in **handler phase**, not earlier hooks

### Request Processing Flow
1. `hook_insert_filter` - Creates context, adds input/output filters
2. `hook_request_late` (as handler) - Reads body, processes headers
3. Input filter intercepts body reads, buffers to ModSecurity
4. Handler processes complete body, checks interventions
5. Returns proper HTTP status code if intervention needed

### Comparison with Nginx Connector
- Nginx: Explicitly calls `ngx_http_read_client_request_body()`
- Apache: Uses `ap_setup_client_block()` + `ap_get_client_block()` loop
- Both: Process body once after complete buffering
- Both: Use flag (`request_body_processed`) to track state

## Testing Infrastructure

### Docker Test Environment
- **Dockerfile:** Multi-stage build (libmodsecurity v3 + Apache 2.4.62 + connector)
- **docker-compose.yml:** Easy container management
- **test-connector.sh:** Automated test suite
- **DOCKER_TEST.md:** Testing documentation

### Test Rules
```
# Query string test
SecRule ARGS:test "@contains evil" \
    "id:1001,phase:2,deny,status:403,msg:'Test rule triggered'"

# Request body test
SecRule REQUEST_BODY "@rx malicious" \
    "id:1002,phase:2,deny,status:403,msg:'Request body rule triggered'"
```

## Files Modified

1. `src/mod_security3.h` - Added `request_body_processed` flag
2. `src/mod_security3.c` - Fixed context creation, moved to handler phase, added body reading
3. `src/msc_filters.c` - Fixed body processing logic, filter removal, error handling
4. `src/msc_utils.c` - Fixed status code bug
5. `Dockerfile` - Created test environment
6. `docker-compose.yml` - Container orchestration
7. `test-connector.sh` - Automated test suite
8. `DOCKER_TEST.md` - Testing documentation

## Performance Considerations

### Before Fixes
- Rules fired N times per request (once per bucket)
- Unnecessary processing overhead
- Incorrect status codes confused clients/proxies

### After Fixes
- Rules fire exactly once per request
- Efficient single-pass body processing
- Proper HTTP status codes

## Known Limitations

### Not Addressed
- Memory leak during graceful restarts (separate issue, not related to these fixes)
- Advanced ModSecurity features may need additional connector work

### Production Readiness
With these fixes, the connector can:
- ✅ Inspect query strings and block malicious requests
- ✅ Inspect request bodies and block malicious content
- ✅ Handle large POST requests (multi-bucket processing)
- ✅ Return proper HTTP status codes (403, etc.)
- ✅ Process rules efficiently (once per request)

## Build and Test Instructions

```bash
# Build Docker image
docker build -t modsec3-apache-test .

# Run container
docker run -d -p 8080:8080 --name modsec3-test modsec3-apache-test

# Run automated tests
./test-connector.sh

# Manual testing
curl http://localhost:8080/                          # Should return 200
curl http://localhost:8080/?test=evil                # Should return 403
curl -X POST http://localhost:8080/ -d "data=malicious"  # Should return 403
```

## References

### Key Resources Used
- Apache Module Developer Documentation
- Other Apache modules (mod_proxy_scgi, mod_proxy_http)
- ModSecurity Nginx connector (for comparison)
- Apache HTTP Server source code

### Critical Learning
The breakthrough came from analyzing other Apache modules to understand that **request body reading must happen in the handler phase**, not in earlier hooks like fixups. This architectural requirement is fundamental to how Apache processes requests.

## Credits

These fixes were implemented by analyzing:
1. The ModSecurity nginx connector implementation
2. Apache's module developer documentation
3. Real Apache modules (mod_proxy_scgi, etc.)
4. GitHub issues discussing the connector's limitations

The fixes address the core issues that prevented the connector from being production-ready.
