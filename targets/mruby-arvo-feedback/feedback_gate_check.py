"""Build-time check: the instrumented binary must be able to report the target site.

The feedback map and the instrumented binary must agree on block and location
IDs, otherwise the harness can never confirm that an input reached the target
operation and silently reports "not reached" for every input (observed when the
map was emitted from the pre-optimization CFG while notifications were inserted
after optimization).

This check runs a witness input that executes the anchor line and asserts that
the map's anchor block ID and at least one anchor location ID are actually
emitted by the binary.

Usage: feedback_gate_check.py MAP BINARY WITNESS SOURCE_FILE FUNCTION LINE
"""

import json
import os
import struct
import subprocess
import sys
import tempfile

TRACE_MAGIC = b"SYMFDB1\0"
TRACE_HEADER = struct.Struct("<8sIIQQII")
TRACE_EVENT = struct.Struct("<QII")
FLAG_COMPLETE = 1 << 0
FLAG_TRUNCATED = 1 << 1


def anchor_ids(map_path: str, source_file: str, function: str, line: int):
    block_ids: set[int] = set()
    location_ids: set[int] = set()
    with open(map_path) as handle:
        for raw in handle:
            record = json.loads(raw)
            if record.get("function") != function:
                continue
            for block in record.get("blocks") or []:
                for location in block.get("source_locations") or []:
                    if (
                        location.get("source_file") == source_file
                        and location.get("line") == line
                    ):
                        block_ids.add(block["id"])
                        location_ids.add(location["id"])
    return block_ids, location_ids


def run_witness(binary: str, witness: str):
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = os.path.join(tmp, "trace.bin")
        env = dict(os.environ)
        env.update(
            {
                "SYMCC_INPUT_FILE": witness,
                "SYMCC_OUTPUT_DIR": os.path.join(tmp, "symcc-out"),
                "SYMCC_FEEDBACK_TRACE": trace_path,
                "SYMCC_FEEDBACK_CAPACITY": "1000000",
                "SYMCC_NO_SYMBOLIC_INPUT": "1",
            },
        )
        os.makedirs(env["SYMCC_OUTPUT_DIR"], exist_ok=True)
        result = subprocess.run(
            [binary, witness], env=env, capture_output=True, timeout=600
        )
        if not os.path.exists(trace_path):
            raise SystemExit(f"ERROR: witness produced no trace (rc={result.returncode})")
        with open(trace_path, "rb") as handle:
            data = handle.read()

    magic, schema, header_size, capacity, count, flags, _reserved = (
        TRACE_HEADER.unpack_from(data)
    )
    if magic != TRACE_MAGIC or schema != 1 or header_size != TRACE_HEADER.size:
        raise SystemExit("ERROR: invalid trace header")
    if count > capacity or header_size + count * TRACE_EVENT.size > len(data):
        raise SystemExit("ERROR: trace event stream is incomplete")
    events = [
        TRACE_EVENT.unpack_from(data, header_size + index * TRACE_EVENT.size)[:2]
        for index in range(count)
    ]
    return result.returncode, flags, events


def main(argv: list[str]) -> int:
    if len(argv) != 7:
        raise SystemExit(
            f"usage: {argv[0]} MAP BINARY WITNESS SOURCE_FILE FUNCTION LINE"
        )
    map_path, binary, witness, source_file, function, line = argv[1:7]
    line = int(line)

    block_ids, location_ids = anchor_ids(map_path, source_file, function, line)
    if not block_ids or not location_ids:
        raise SystemExit(
            f"ERROR: map has no block/location covering {source_file}:{line} "
            f"in {function}"
        )
    print(
        f"anchor {source_file}:{line} {function}: "
        f"{len(block_ids)} block(s), {len(location_ids)} location(s)"
    )

    rc, flags, events = run_witness(binary, witness)
    if not flags & FLAG_COMPLETE or flags & FLAG_TRUNCATED:
        raise SystemExit("ERROR: witness trace is incomplete or truncated")
    observed_blocks = {site for site, kind in events if kind == 1}
    observed_locations = {site for site, kind in events if kind == 2}
    hit_blocks = block_ids & observed_blocks
    hit_locations = location_ids & observed_locations
    print(
        f"witness rc={rc} events={len(events)}: anchor blocks emitted "
        f"{len(hit_blocks)}/{len(block_ids)}, anchor locations emitted "
        f"{len(hit_locations)}/{len(location_ids)}"
    )
    if not hit_blocks or not hit_locations:
        raise SystemExit(
            "ERROR: the instrumented binary never emitted the map's anchor "
            "IDs; the feedback map does not describe this binary",
        )
    print("feedback gate check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
