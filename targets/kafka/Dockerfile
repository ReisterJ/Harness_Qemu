# Apache Kafka 4.4.0-rc0 — Java memory-error target
# Build: JDK 17 + Gradle wrapper. Only the pure-Java `clients` module is
# compiled (fastest reliable path); Scala modules (core/streams) are skipped.
# "Crash" for Java = JVM exits non-zero with an uncaught memory-class error
# (OutOfMemoryError / StackOverflowError / BufferUnderflow-Overflow /
# ArrayIndexOutOfBoundsException) under the tight-heap JVM flags below.
#
# Build needs network (git clone + gradle deps): run with
#   VULN_PIPELINE_DOCKER_BUILD_NETWORK=host
# and pass the proxy at build time, e.g.
#   --build-arg HTTPS_PROXY=http://127.0.0.1:7897 --build-arg HTTP_PROXY=http://127.0.0.1:7897
FROM eclipse-temurin:17-jdk

ARG HTTPS_PROXY=
ARG HTTP_PROXY=
ENV HTTPS_PROXY=${HTTPS_PROXY} HTTP_PROXY=${HTTP_PROXY} http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

RUN apt-get update && apt-get install -y --no-install-recommends git python3 xxd file && rm -rf /var/lib/apt/lists/*

# Kafka source at the exact RC tag (shallow).
RUN git clone --depth 1 --branch 4.4.0-rc0 https://github.com/apache/kafka.git /work/kafka

# Build only the clients module (Java, no Scala). Gradle pulls deps from Maven Central.
WORKDIR /work/kafka
RUN ./gradlew :clients:jar -x test --no-daemon -PskipSigning=true --max-workers=2 -Dorg.gradle.internal.http.connectionTimeout=180000 -Dorg.gradle.internal.http.socketTimeout=180000 || ./gradlew :clients:jar -x test --no-daemon -PskipSigning=true --max-workers=2 -Dorg.gradle.internal.http.connectionTimeout=180000 -Dorg.gradle.internal.http.socketTimeout=180000

# Harness + run script
COPY Harness.java /work/Harness.java
COPY run_harness.sh /work/run_harness.sh
RUN chmod +x /work/run_harness.sh

# Compile the harness against clients jar + all gradle-cached deps, and freeze
# the classpath so the run script needs no re-discovery at runtime.
RUN mkdir -p /work/classes && \
    CP="/work/kafka/clients/build/libs/*:$(find /root/.gradle/caches -name '*.jar' | tr '\n' ':')" && \
    echo "$CP" > /work/classpath.txt && \
    javac -cp "$CP" /work/Harness.java -d /work/classes

# Drop the proxy env once the image is built (agents have no egress anyway).
ENV HTTPS_PROXY= HTTP_PROXY= http_proxy= https_proxy=

WORKDIR /work
