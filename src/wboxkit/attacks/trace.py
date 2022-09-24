#!/usr/bin/env pypy3

import sys, os
import argparse
import random

from pathlib import Path

from wboxkit.fastcircuit import FastCircuit, chunks
from wboxkit.tracing import trace_split_batch
from wboxkit.attacks.reader import Reader

PATH_FORMAT_TRACE = "%04d.bin"
PATH_FORMAT_TMP = ".chunk%04d.bin"
PATH_FORMAT_PT = "%04d.pt"
PATH_FORMAT_CT = "%04d.ct"


def main():
    parser = argparse.ArgumentParser(
        description='Trace Boolean circuit serialized by wboxkit on random inputs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        'circuit', type=Path,
        help="File with serialized circuit"
    )
    parser.add_argument(
        'traces_dir', type=Path,
        help=(
            "path to directory with trace/plaintext/ciphertext files"
            " (subfolder with the circuit's file_name will be created)"
        )
    )

    parser.add_argument(
        '-t', '-T', '--n-traces', type=int, default=512,
        help="number of traces to record"
    )

    parser.add_argument(
        '--seed', type=int, default=0,
        help="seed to generate plaintexts"
    )


    args = parser.parse_args()

    NAME = args.circuit.name
    if NAME.endswith(".bin"):
        NAME = NAME[:-4]

    FC = FastCircuit(str(args.circuit))
    N = args.n_traces
    TRACE_FOLDER = args.traces_dir
    PREFIX = TRACE_FOLDER / NAME
    assert "%" not in str(PREFIX)

    print("Tracing", args.circuit, "on", N, "traces")
    print("Saving to", PREFIX)

    PREFIX.mkdir(exist_ok=True)

    random.seed(args.seed)

    n_input_bytes = (FC.info.input_size + 7) // 8
    pts = [
        bytes([random.getrandbits(8) for _ in range(n_input_bytes)])
        for _ in range(N)
    ]

    cts = FC.compute_batches(
        inputs=pts,
        trace_filename_format=str(PREFIX / PATH_FORMAT_TMP)
    )
    for i in range((N+63)//64):
        print("splitting", i)
        filename = PREFIX / (PATH_FORMAT_TMP % i)
        trace_split_batch(
            filename=filename,
            make_output_filename=
                lambda j: PREFIX / (PATH_FORMAT_TRACE % (i * 64 + j)),
            ntraces=64,
            packed=True)
        os.unlink(filename)

    for i, (pt, ct) in enumerate(zip(pts, cts)):
        with open(PREFIX / (PATH_FORMAT_PT % i), "wb") as f:
            f.write(pt)
        with open(PREFIX / (PATH_FORMAT_CT % i), "wb") as f:
            f.write(ct)


if __name__ == '__main__':
    main()
