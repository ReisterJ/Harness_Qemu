# Kafka 4.4.0-rc0 target (Java)

Memory-system experiment target on a large real-world Java codebase.

## Why Java / why this target

- Much larger and more function-dense than libyaml (kafka-clients alone is
  thousands of classes) — the function-index memory design should show its
  value (skip fully-explored functions, prioritize SUSPICIOUS, cover more).
- Real-world Java target: exercises the harness against a non-C/ASAN stack.

## Java memory-error detection (no ASAN)

Java has no AddressSanitizer. The pipeline treats these as the "crash" signal:

| Java error | Trigger | Detection |
|---|---|---|
| `OutOfMemoryError` (heap) | input-controlled huge allocation | `-Xmx512m -XX:+ExitOnOutOfMemoryError` → non-zero exit |
| `OutOfMemoryError` (direct) | ByteBuffer.allocateDirect from size field | `-XX:MaxDirectMemorySize=256m` |
| `StackOverflowError` | unbounded recursion | uncaught → non-zero exit |
| `BufferUnderflow/OverflowException` | NIO bounds violation | uncaught → non-zero exit |
| `ArrayIndexOutOfBoundsException` | unchecked index | uncaught → non-zero exit |
| AssertionError | invariant violation | `-ea` |

Forensics: `-XX:+HeapDumpOnOutOfMemoryError` writes a heap dump on OOM.

**Important:** Kafka *gracefully* rejects malformed input with
`SchemaException` / `IllegalArgumentException` — that is correct behavior,
NOT a bug. A valid find is an *unexpected* memory-class error reachable from
attacker-controlled input (unchecked size → allocation, unchecked index,
unbounded recursion, integer overflow in `position+size`).

## Entry point

`/work/run_harness.sh <file>` — runs `Harness` (RecordBatch parser) under the
tight-heap JVM. Agents can compile their own harness variants:

```bash
javac -cp "$(cat /work/classpath.txt)" /tmp/MyHarness.java -d /tmp
java -Xmx512m -XX:+ExitOnOutOfMemoryError -cp "/tmp:$(cat /work/classpath.txt)" MyHarness /tmp/input
```

## Build

```bash
VULN_PIPELINE_DOCKER_BUILD_NETWORK=host \
  docker build --network=host --build-arg HTTPS_PROXY=http://127.0.0.1:7897 \
  --build-arg HTTP_PROXY=http://127.0.0.1:7897 -t vuln-pipeline-kafka:latest targets/kafka/
```

Only `:clients:jar` is built (pure Java); Scala modules (core/streams) are
skipped to keep the build feasible.

## Run

```bash
vuln-pipeline run targets/kafka --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 [--memory]
```
