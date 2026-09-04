# curl 8.22.0 target (C / ASAN)

Memory-system experiment target on a large real-world C codebase (the curl
client library + CLI — thousands of functions, ideal for the function-index
memory design: skip fully-explored functions, prioritize SUSPICIOUS).

## Entry point

`/work/run_curl.sh <file>` — serves the file's bytes verbatim as a raw HTTP
response from a local TCP server, then runs the **ASAN-instrumented** curl
(`/work/curl/src/curl`) against `http://127.0.0.1:<port>/x`. A memory error
in curl's response parsing aborts with an ASAN report + non-zero exit.

Craft any raw response to reach different parsers:

```bash
# plain
printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc' > /tmp/r
# chunked transfer-encoding edge
printf 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\nx\r\n0\r\n\r\n' > /tmp/r2
# gzip content-encoding (bogus stream)
python3 -c "import gzip,sys; b=gzip.compress(b'A'*1000); sys.stdout.buffer.write(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: '+str(len(b)).encode()+b'\r\n\r\n'+b)" > /tmp/r3
/work/run_curl.sh /tmp/r
```

## Build

```bash
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host \
  docker build --network=host --build-arg HTTPS_PROXY=http://127.0.0.1:7897 \
  --build-arg HTTP_PROXY=http://127.0.0.1:7897 -t vuln-pipeline-curl:latest targets/curl/
```

Configure keeps the parsing surface (http / content-encoding+zlib / cookie /
url) and disables SSL + optional codecs for build stability. The built curl is
`/work/curl/src/curl`.

## Run

```bash
vuln-pipeline run targets/curl --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 [--memory]
```

Note: max_turns is a budget, not a quota — agents that land a crash submit and
stop early (see docs/MEMORY_EXPERIMENT_RESULTS.md §on turn normalization).
