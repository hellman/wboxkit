#!/usr/bin/env python3

import argparse
import pathlib
import sys, os, string

from random import sample

from itertools import product
from collections import defaultdict

from sbox import sbox, rsbox
from reader import Reader


parser = argparse.ArgumentParser(
    description='Apply "Exact Matching Attack" on pre-recorder traces.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    'trace_dir', type=pathlib.Path,
    help="path to directory with trace/plaintext/ciphertext files")
parser.add_argument(
    '-T', '--n-traces', type=int, default=500,
    help="number of traces to combine"
)

args = parser.parse_args()

T = args.n_traces

packed = True

pts = []
cts = []

fname_pt = args.trace_dir / "all.input"
fname_ct = args.trace_dir / "all.output"
fname_t = args.trace_dir / "all.bin"

out_pt = open(fname_pt, "wb")
out_ct = open(fname_ct, "wb")
out_t = open(fname_t, "wb")

nsamples = None

def expand_byte(b):
    res = []
    for i in range(8):
        res.append(b"\x00\x01"[(b >> (7 - i & 7)) & 1])
    return bytes(res)


for i in range(T):
    fpt = args.trace_dir / ("%04d.pt" % i)
    fct = args.trace_dir / ("%04d.ct" % i)
    ft = args.trace_dir / ("%04d.bin" % i)

    with open(fpt, "rb") as f:
        pt = f.read(16)
    with open(fct, "rb") as f:
        ct = f.read(16)
    with open(ft, "rb") as f:
        trace = f.read()

    if packed:
        trace = b"".join(map(expand_byte, trace))

    if nsamples is None:
        nsamples = len(trace)
    else:
        assert nsamples == len(trace)

    out_pt.write(pt)
    out_ct.write(ct)
    out_t.write(trace)

print(T, "traces")

config = f"""
[Traces]
files=1
trace_type=i
transpose=true
index=0
nsamples={nsamples}
trace={fname_t} {T} {nsamples}

[Guesses]
files=1
guess_type=u
transpose=true
guess={fname_pt} {T} 16

[General]
threads=8
order=1
//window=0
return_type=double
algorithm=AES
position=attacks/AES_AFTER_SBOX
round=0
bitnum=0
bytenum=all
//correct_key=???
memory=4G
top=20
"""

with open("daredevil.config", "w") as f:
    f.write(config)
