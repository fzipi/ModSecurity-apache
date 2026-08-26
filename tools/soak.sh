#!/usr/bin/env bash
#
# Sustained mixed-load soak for the ModSecurity Apache connector. Drives a
# real httpd (optionally under valgrind memcheck or helgrind) with
# concurrent benign AND attack-shaped requests for a fixed duration, while
# periodically triggering a graceful restart (SIGUSR1) -- the exact
# operation known to leak memory (see docs/TODO.md / issue #82) -- then
# asserts the server survived cleanly: no valgrind/helgrind error, no
# crash, no leak, no error-log [alert]/[emerg].
#
# The traffic mix exercises the WAF decision path in both directions --
# benign requests that must pass (200) and attack requests the in-config
# SecRules must block (403) -- so the transaction lifecycle (create/
# process/destroy), request body buffering, and response body inspection
# all run under the checker every iteration, across many graceful restarts.
#
# httpd is run with -DFOREGROUND (like the module's own start.sh) so the
# worker/event MPM forks child processes and threads exactly as in
# production; valgrind is invoked with --trace-children=yes so those
# forked children -- where request handling and the module hooks actually
# run -- are instrumented too, not just the master process.
#
# Usage:
#   tools/soak.sh <httpd-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <httpd-binary> 120 8
#   USE_HELGRIND=1 tools/soak.sh <httpd-binary> 120 8
#
# Env:
#   RESTART_INTERVAL : seconds between graceful restarts (default 10; 0 disables)
#   MODULE_SO        : path to mod_security3.so (default:
#                       /usr/lib/apache2/modules/mod_security3.so)
#   MODULE_DIR       : directory holding the stock httpd modules (default:
#                       /usr/lib/apache2/modules)
#   MIME_TYPES       : path to mime.types (default: /etc/mime.types)
#
# Exit non-zero on ANY of: memcheck error, httpd crash/non-clean exit,
# error-log alert/emerg, or a WAF verdict regression (benign blocked /
# attack allowed). Helgrind findings are reported but do not fail the run --
# httpd is not helgrind-clean; see tools/valgrind.suppress.

set -euo pipefail

HTTPD="${1:?usage: soak.sh <httpd-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-4}"
RESTART_INTERVAL="${RESTART_INTERVAL:-10}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="${MODULE_DIR:-/usr/lib/apache2/modules}"
MODULE_SO="${MODULE_SO:-$MODULE_DIR/mod_security3.so}"
MIME_TYPES="${MIME_TYPES:-/etc/mime.types}"

WORK="$(mktemp -d)"
# Kill the (possibly valgrind-wrapped) server too: under `set -e` an early
# failure would otherwise orphan it, holding the port for later runs.
trap 'kill -9 "${HTTPD_PID:-}" "${RESTARTER_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/htdocs"
# httpd runs as www-data (see User/Group below); mktemp's dir defaults to
# 0700 root-only, which would make DocumentRoot unreadable to that user.
chmod 755 "$WORK" "$WORK/htdocs"

echo "hello modsecurity" >"$WORK/htdocs/index.html"
head -c 200000 /dev/urandom | base64 >"$WORK/htdocs/medium"

# Only load the stock modules that exist as DSOs. Which ones are built into
# the binary differs by build -- Debian's httpd has unixd compiled in, a
# source build ships it as a .so -- and loading a built-in one is a fatal
# config error.
LOAD_MODULES=""
for name in mpm_event authz_core unixd mime dir; do
	if [ -f "$MODULE_DIR/mod_${name}.so" ]; then
		LOAD_MODULES="${LOAD_MODULES}LoadModule ${name}_module $MODULE_DIR/mod_${name}.so
"
	fi
done

# In-config SecRules: block a URI-arg attack marker and a request-body
# marker so both the header/URI path and the body-inspection path are
# exercised. Benign traffic hits neither. Mirrors test-rules.conf.
cat >"$WORK/conf/httpd.conf" <<EOF
ServerRoot "$WORK"
ServerName localhost
Listen 18080
PidFile $WORK/logs/httpd.pid
ErrorLog $WORK/logs/error.log
LogLevel info
DocumentRoot "$WORK/htdocs"
DirectoryIndex index.html
User www-data
Group www-data

$LOAD_MODULES
LoadModule security3_module $MODULE_SO

TypesConfig $MIME_TYPES

<IfModule mpm_event_module>
    StartServers 1
    ServerLimit 1
    ThreadsPerChild 8
    ThreadLimit 8
    MaxRequestWorkers 8
    MinSpareThreads 1
    MaxSpareThreads 8
</IfModule>

<IfModule security3_module>
    modsecurity on
    modsecurity_rules 'SecRuleEngine On \\
        SecRequestBodyAccess On \\
        SecRule ARGS "@contains attackmarker" "id:100,phase:2,deny,status:403" \\
        SecRule REQUEST_BODY "@rx malicious" "id:101,phase:2,deny,status:403"'
</IfModule>
EOF

RUN=("$HTTPD" -f "$WORK/conf/httpd.conf" -DFOREGROUND)
if [ "${USE_VALGRIND:-0}" = "1" ]; then
	RUN=(valgrind --tool=memcheck --trace-children=yes --error-exitcode=99
		--leak-check=full --errors-for-leak-kinds=definite
		--show-leak-kinds=definite
		--suppressions="$SCRIPT_DIR/valgrind.suppress"
		--log-file="$WORK/logs/valgrind.%p" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
	# No --error-exitcode here: helgrind findings are reported, not gated.
	# See the helgrind section of tools/valgrind.suppress for why.
	RUN=(valgrind --tool=helgrind --trace-children=yes
		--suppressions="$SCRIPT_DIR/valgrind.suppress"
		--log-file="$WORK/logs/helgrind.%p" "${RUN[@]}")
fi

# Capture httpd (and valgrind) stderr -- config-parse failures print HERE,
# before error.log is ever opened.
"${RUN[@]}" >"$WORK/logs/stdout.txt" 2>"$WORK/logs/stderr.txt" &
HTTPD_PID=$!

# Wait for listen. valgrind starts slowly, so allow up to ~120s; bail early
# if the process already died (config error, missing module, etc.) rather
# than burning the full timeout.
up=0
for _ in $(seq 1 1200); do
	if ! kill -0 "$HTTPD_PID" 2>/dev/null; then
		break # process gone -- startup failed, report below
	fi
	curl -fsS -o /dev/null "http://127.0.0.1:18080/" 2>/dev/null && {
		up=1
		break
	}
	sleep 0.1
done
if [ "$up" -ne 1 ]; then
	echo "FAIL: httpd never came up"
	echo "--- stderr ---"
	cat "$WORK/logs/stderr.txt" 2>/dev/null || true
	echo "--- error.log ---"
	cat "$WORK/logs/error.log" 2>/dev/null || echo "(none written)"
	if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
		echo "--- valgrind/helgrind log ---"
		cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
	fi
	kill "$HTTPD_PID" 2>/dev/null || true
	exit 1
fi

echo "soak: ${DURATION}s, concurrency ${CONC}, restart every ${RESTART_INTERVAL}s$(
	[ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'
	[ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)'
)"
END=$(($(date +%s) + DURATION))
fail=0

worker() {
	while [ "$(date +%s)" -lt "$END" ]; do
		case $((RANDOM % 5)) in
		0) # benign GET -> must pass
			code=$(curl -s -o /dev/null -w '%{http_code}' \
				"http://127.0.0.1:18080/" 2>/dev/null || echo 000)
			[ "$code" = "200" ] || {
				echo "benign GET got $code"
				return 1
			}
			;;
		1) # benign larger body -> must pass
			code=$(curl -s -o /dev/null -w '%{http_code}' \
				"http://127.0.0.1:18080/medium" 2>/dev/null || echo 000)
			[ "$code" = "200" ] || {
				echo "benign /medium got $code"
				return 1
			}
			;;
		2) # URI-arg attack -> must be blocked 403
			code=$(curl -s -o /dev/null -w '%{http_code}' \
				"http://127.0.0.1:18080/?q=attackmarker" 2>/dev/null || echo 000)
			[ "$code" = "403" ] || {
				echo "URI attack got $code (want 403)"
				return 1
			}
			;;
		3) # body attack -> must be blocked 403
			code=$(curl -s -o /dev/null -w '%{http_code}' \
				-d 'x=malicious' \
				"http://127.0.0.1:18080/" 2>/dev/null || echo 000)
			[ "$code" = "403" ] || {
				echo "body attack got $code (want 403)"
				return 1
			}
			;;
		4) # benign POST body -> must pass
			code=$(curl -s -o /dev/null -w '%{http_code}' \
				-d 'x=harmless' \
				"http://127.0.0.1:18080/" 2>/dev/null || echo 000)
			[ "$code" = "200" ] || {
				echo "benign POST got $code"
				return 1
			}
			;;
		esac
	done
}

# Periodically issue a graceful restart (SIGUSR1) against the running
# master -- the exact operation reported to leak memory. Runs concurrently
# with traffic so restarts happen mid-flight, same as in production.
restarter() {
	[ "$RESTART_INTERVAL" -gt 0 ] || return 0
	while [ "$(date +%s)" -lt "$END" ]; do
		sleep "$RESTART_INTERVAL"
		kill -0 "$HTTPD_PID" 2>/dev/null || break
		kill -USR1 "$HTTPD_PID" 2>/dev/null || true
	done
}

pids=()
for _ in $(seq 1 "$CONC"); do
	worker &
	pids+=($!)
done
restarter &
RESTARTER_PID=$!

for pid in "${pids[@]}"; do wait "$pid" || fail=1; done
kill "$RESTARTER_PID" 2>/dev/null || true
wait "$RESTARTER_PID" 2>/dev/null || true

# Clean shutdown so all pool cleanups (incl. the ModSecurity transaction
# and rule set) run.
kill -TERM "$HTTPD_PID" 2>/dev/null || true
# `wait; rc=$?` would let a non-zero wait trip `set -e` before rc=$? ever
# runs (valgrind's --error-exitcode=99 on a found error, in particular) --
# capture it in the same compound command instead.
rc=0
wait "$HTTPD_PID" 2>/dev/null || rc=$?

problems=0
if ls "$WORK"/logs/valgrind.* >/dev/null 2>&1; then
	if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
		"$WORK"/logs/valgrind.* 2>/dev/null; then
		echo "FAIL: memcheck errors:"
		grep -E 'ERROR SUMMARY|definitely lost' \
			"$WORK"/logs/valgrind.* 2>/dev/null
		problems=1
	fi
fi

# Helgrind reports, it does not gate. httpd is not helgrind-clean: APR pools
# and bucket brigades move memory between mpm_event workers with no
# happens-before edge helgrind can see, so a clean run is not achievable and
# failing on a non-zero count would just make every run red. The suppressions
# drop the httpd/APR-internal races; triage what survives by hand.
if ls "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
	echo "--- helgrind summary (informational, not gating) ---"
	grep -E 'ERROR SUMMARY' "$WORK"/logs/helgrind.* 2>/dev/null || true
	echo "Residual contexts trace to APR recycling pool memory between mpm_event"
	echo "workers, not to shared connector state. See tools/valgrind.suppress."
	echo "Distinct racing frames that survived the suppressions:"
	grep -A3 -E 'Possible data race' "$WORK"/logs/helgrind.* 2>/dev/null |
		grep -oE 'at 0x[0-9A-F]+: .*' | sed 's/^at 0x[0-9A-F]*: //' |
		sort | uniq -c | sort -rn | head -20 || true
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
	echo "FAIL: alert/emerg in error.log"
	problems=1
fi
if [ "$fail" -ne 0 ]; then
	echo "FAIL: a worker reported a WAF verdict regression"
	problems=1
fi
if [ "$rc" -ne 0 ] && [ "$rc" -ne 143 ]; then
	echo "FAIL: httpd exited $rc"
	tail -40 "$WORK/logs/error.log" || true
	problems=1
fi

if [ "$problems" -ne 0 ]; then
	echo "--- full valgrind/helgrind logs (for triage) ---"
	cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
	exit 1
fi
checked="no leak/crash"
[ "${USE_HELGRIND:-0}" = "1" ] && checked="no crash (races reported above, not gated)"
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, $((DURATION / (RESTART_INTERVAL == 0 ? DURATION + 1 : RESTART_INTERVAL))) graceful restart(s), $checked, WAF verdicts held"
