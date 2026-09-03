#!/bin/bash
# Kafka harness runner — the vuln-pipeline "binary".
# Runs Harness (RecordBatch parser) under tight-heap JVM with memory-error
# detection flags. Exit code non-zero + memory-class exception on stderr =
# the Java equivalent of an ASAN crash.
CP="$(cat /work/classpath.txt)"
exec java -Xmx512m -XX:MaxDirectMemorySize=256m -XX:+ExitOnOutOfMemoryError \
  -XX:+HeapDumpOnOutOfMemoryError -ea \
  -cp "/work/classes:${CP}" Harness "$@"
