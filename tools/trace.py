#!/usr/bin/env python

import sys, os
from wbkit.fastcircuit import FastCircuit, chunks
from wbkit.tracing import trace_split_batch

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <circuit_file> <n_traces> <trace_folder>")
    print("Traces saved to the./traces/ folder")
    quit()

NAME = os.path.basename(sys.argv[1])
if NAME.endswith(".bin"):
    NAME = NAME[:-4]

FC = FastCircuit(sys.argv[1])
N = int(sys.argv[2])
TRACE_FOLDER = sys.argv[3]
PREFIX = TRACE_FOLDER + "/" + NAME + "/"

print("Tracing", sys.argv[1], "on", N, "traces")
print("Saving to", PREFIX)

os.makedirs(PREFIX, exist_ok=True)



pts = [os.urandom(16) for _ in range(N)]

cts = FC.compute_batches(
    inputs=pts,
    trace_filename_format=PREFIX + ".chunk%d"
)
for i in range((N+63)//64):
    print("splitting", i)
    filename = PREFIX + ".chunk%d" % i
    trace_split_batch(
        filename=filename,
        make_output_filename=
            lambda j: PREFIX + "%04d.bin" % (i * 64 + j),
        ntraces=64,
        packed=True)
    os.unlink(filename)

for i, (pt, ct) in enumerate(zip(pts, cts)):
    with open(PREFIX + "%04d.pt" % i, "wb") as f:
        f.write(pt)
    with open(PREFIX + "%04d.ct" % i, "wb") as f:
        f.write(ct)
