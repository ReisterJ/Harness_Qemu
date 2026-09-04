#!/bin/bash
# curl harness — the vuln-pipeline "binary" for the curl target.
#
# usage: run_curl.sh <http_response_file>
#
# The file's bytes are served verbatim as the raw HTTP response (status line +
# headers + blank line + body) by a tiny local TCP server; the ASAN-instrumented
# curl then requests http://127.0.0.1:<port>/x and parses that response.
# A memory error in curl's response parsing aborts with an ASAN report +
# non-zero exit — the C equivalent of the earlier targets.
#
# Agents may craft any raw response: huge/chunked bodies, malformed headers,
# Content-Encoding: gzip streams, Set-Cookie soup, bad status lines, etc.

RESP="$1"
if [ ! -f "$RESP" ]; then
    echo "usage: run_curl.sh <response_file>" >&2
    exit 2
fi

# Raw response server: read one request, send the whole response, close.
python3 - "$RESP" <<'PY' &
import socket, sys
resp = open(sys.argv[1], 'rb').read()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
port = s.getsockname()[1]
with open('/tmp/curl_port', 'w') as f:
    f.write(str(port))
conn, _ = s.accept()
try:
    conn.settimeout(10)
    conn.recv(65536)          # read the GET
    conn.sendall(resp)        # serve the crafted response
except Exception:
    pass
conn.close()
s.close()
PY

# Wait for the port file, then run ASAN curl against the response.
for _ in $(seq 1 100); do
    [ -f /tmp/curl_port ] && break
    sleep 0.05
done
PORT=$(cat /tmp/curl_port 2>/dev/null)
rm -f /tmp/curl_port
if [ -z "$PORT" ]; then
    echo "server failed to start" >&2
    exit 2
fi

exec /work/curl/build/src/curl -s -o /dev/null --max-time 20 "http://127.0.0.1:${PORT}/x"
