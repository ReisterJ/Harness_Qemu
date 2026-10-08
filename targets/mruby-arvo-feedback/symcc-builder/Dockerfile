# SymCC instrumenter with the feedback ID-cache fix (2026-10-07).
#
# The map is emitted from the pipeline-start CFG, but notifications are
# inserted before the vectorizer and would recompute block IDs from the
# optimized CFG; instrumentation splits and adds blocks, so the IDs drifted and
# the harness could never match a target ID.  Feedback.h caches the IDs
# computed during map emission and reuses them for the notifications.
#
# Build from this directory:
#   docker build -t local/symcc-target-feedback:20261007-idcache .
FROM local/symcc-target-feedback:20260924-sitefix1
USER root
COPY Feedback.h /symcc-feedback-source/compiler/Feedback.h
RUN ninja -C /symcc-feedback-build
