#!/bin/bash
# Test script for ModSecurity v3 Apache Connector
# Tests the fixes for request body processing and other bugs

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASEURL="http://localhost:8080"
PASSED=0
FAILED=0

echo "======================================"
echo "ModSecurity v3 Apache Connector Tests"
echo "======================================"
echo ""

# Function to test requests
test_request() {
    local name="$1"
    local url="$2"
    local expected_status="$3"
    local method="${4:-GET}"
    local data="${5:-}"

    echo -n "Testing: $name ... "

    if [ "$method" = "POST" ]; then
        actual_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "$url")
    else
        actual_status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    fi

    if [ "$actual_status" = "$expected_status" ]; then
        echo -e "${GREEN}PASS${NC} (got $actual_status)"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC} (expected $expected_status, got $actual_status)"
        FAILED=$((FAILED + 1))
    fi
}

# Wait for service to be ready
echo "Waiting for Apache to be ready..."
for i in {1..30}; do
    if curl -s "$BASEURL" > /dev/null 2>&1; then
        echo -e "${GREEN}Apache is ready!${NC}"
        echo ""
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}Timeout waiting for Apache${NC}"
        exit 1
    fi
    sleep 1
done

echo "Running tests..."
echo ""

# Test 1: Normal request (should work)
test_request "Normal request" "$BASEURL/" "200"

# Test 2: Query string rule trigger (should be blocked)
test_request "Query string rule (should block)" "$BASEURL/?test=evil" "403"

# Test 3: POST with malicious body (should be blocked)
test_request "Request body rule (should block)" "$BASEURL/" "403" "POST" "data=malicious"

# Test 4: Normal POST (should work)
test_request "Normal POST request" "$BASEURL/" "200" "POST" "data=normal"

# Test 5: Large POST (tests bucket processing fix - multiple chunks)
echo -n "Testing: Large POST (multi-bucket) ... "
large_data=$(head -c 10000 /dev/zero | tr '\0' 'A')
actual_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$large_data" "$BASEURL/")
if [ "$actual_status" = "200" ]; then
    echo -e "${GREEN}PASS${NC} (got $actual_status)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (expected 200, got $actual_status)"
    FAILED=$((FAILED + 1))
fi

# Test 6: Large POST with malicious content (should be blocked, tests our fix)
echo -n "Testing: Large POST with evil content ... "
large_evil_data="A$(head -c 9000 /dev/zero | tr '\0' 'A')malicious"
actual_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$large_evil_data" "$BASEURL/")
if [ "$actual_status" = "403" ]; then
    echo -e "${GREEN}PASS${NC} (got $actual_status - rule fired correctly on multi-bucket body)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (expected 403, got $actual_status - this tests the request body processing fix!)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "======================================"
echo "Test Results"
echo "======================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo ""
    echo "Key fixes verified:"
    echo "  ✓ Request body processing (rules fire once, not per bucket)"
    echo "  ✓ Status codes work correctly (403 is returned)"
    echo "  ✓ Multi-bucket POST requests processed correctly"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    echo ""
    echo "Check logs:"
    echo "  docker logs modsec3-apache-test"
    echo "  cat logs/error.log"
    exit 1
fi
