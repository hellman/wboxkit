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
    description='Apply "Exact Matching Attack" on pre-recorded traces.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    'trace_dir', type=pathlib.Path,
    help="path to directory with trace/plaintext/ciphertext files")
parser.add_argument(
    '-T', '--n-traces', type=int, default=100,
    help="number of traces to use in the attack"
)
parser.add_argument(
    '-w', '--window', type=int, default=2048,
    help="sliding window size"
)
parser.add_argument(
    '-s', '--step', type=int, default=1024,
    help="sliding window step",
)
parser.add_argument(
    '--masks', default="1,2,4,8,16,32,64,128",
    help=(
        "linear masks to consider"
        " (comma separated ints, or 'all', or 'random16', 'random32')"
    )
)
parser.add_argument(
    '-o', '--order', type=int, default=1,
    help="attack order (1 or 2)",
)
parser.add_argument(
    '--pos', default="0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
    help="byte positions to attack",
)

# parser.add_argument(
#     '--candidate-limit', type=int, default=8,
#     help="limit of key candidates per S-box",
# )

args = parser.parse_args()

# go from the end of the traces if we attack last S-Boxes ?
REVERSE = False # not supported yet

if args.step > args.window:
    print("step larger than the window size, reducing to window/4")
    args.step = args.window // 4


R = Reader(
    ntraces=args.n_traces,
    window=args.window,
    step=args.step,
    packed=True,
    reverse=REVERSE,
    dir=args.trace_dir,
)


STOP_ON_FIRST_MATCH = 0
ONE_CANDIDATE_PER_SBOX = 0

# second order should break 1-st order linear masking
if args.order == 1:
    ENABLE_SECOND_ORDER = 0
elif args.order == 2:
    ENABLE_SECOND_ORDER = 1
else:
    print("unsupported order", args.order, "(only 1 and 2 now)")
    quit()


# attack last S-Box?
CT_SIDE = REVERSE

# which/how many  S-Boxes to attack
BYTE_INDICES = tuple(map(int, args.pos.split(",")))
assert set(BYTE_INDICES) <= set(range(16))

# charset for key bytes
KS = range(256)
# KS = map(ord, string.printable) # only printable characters

# linear masks to check after S-Box, for example
# 0xff will try to match scalar_product(SBox(x xor k), 0b11111111)
# 1 matches the last output bit

if args.masks == 'all':
    args.masks = tuple(range(1, 256))
elif args.masks == 'random16':
    pool = [i for i in range(1, 2**8) if i & (i - 1)]  # not powers of 2
    args.masks = tuple(2**i for i in range(8)) + tuple(sample(pool, 16-8))
elif args.masks == 'random32':
    pool = [i for i in range(1, 2**8) if i & (i - 1)]  # not powers of 2
    args.masks = tuple(2**i for i in range(8)) + tuple(sample(pool, 32-8))

if isinstance(args.masks, str):
    args.masks = tuple(map(int, args.masks.split(",")))

assert isinstance(args.masks, tuple)

LINS = args.masks


def scalar_bin(a, b):
    v = a & b
    res = 0
    while v:
        res ^= v & 1
        v >>= 1
    return res

MASK = 2**R.ntraces - 1

print( "Total traces:", R.ntraces, "of size", "%.1fK bits (%d)" % (R.trace_bytes / 1000.0, R.trace_bytes) )

print("Using linear masks:", LINS)

#== Generate predicted vectors from plaintext/ciphertext and key guess

targets = []
for si, lin, k in product(BYTE_INDICES, LINS, KS):
    target = 0
    for p, c in zip(R.pts, R.cts):
        if k is None:
            if CT_SIDE:
                x = (c[si])
            else:
                x = (p[si])
        else:
            if CT_SIDE:
                x = (c[si])
                x = rsbox[x ^ k]
            else:
                x = (p[si])
                x = sbox[x ^ k]
        target = (target << 1) | scalar_bin(x, lin)

    targets.append((target, (si, lin, k, 0)))
    targets.append((target ^ MASK, (si, lin, k, 1)))

n_matches = [0] * 16

print( "Generated %d target vectors" % len(targets) )
g_candidates = [set() for _ in range(16)]

#== Read traces and analyze
for i_window, vectors in enumerate(R):
    print( "Window %d" % (i_window+1), "/", R.num_windows, )

    print( "offset %d-%d (of %d)" % (R.offset*8, R.offset*8 + len(vectors), R.trace_bytes*8) )
    print( "   ", len(vectors), "vectors" )

    vectors_rev = defaultdict(list)
    for off, v in enumerate(vectors):
        vectors_rev[v].append(R.offset + off)

    print( "   ", len(vectors_rev), "unique vectors" )
    print( "   ", len(targets), "target vectors" )

    candidates = [set() for _ in range(16)]
    key_found = False

    for target, kinfo in targets:
        si, lin, k, const1 = kinfo
        if ONE_CANDIDATE_PER_SBOX and candidates[si]:
            continue

        # single value
        if target in vectors_rev:
            print( "MATCH (SINGLE):", )
            print( "sbox #%d," % si, )
            print( "lin.mask 0x%02x," % lin, )
            print( "key 0x%02x=%r," % (k, chr(k)), )
            print( "negated? %s," % bool(const1), )
            # linear combination indexes (may be non-unique)
            inds = vectors_rev[target][:10]
            print( "indexes", "(%d total)" % len(vectors_rev[target]), inds, )
            print( )

            candidates[si].add(k)
            g_candidates[si].add(k)
            n_matches[si] += 1
            key_found = True

        if ENABLE_SECOND_ORDER:
            # shared in 2 shares
            for v1 in vectors_rev:
                if v1 in (0, MASK):
                    continue
                v2 = target ^ v1
                if v2 in vectors_rev:
                    print( "MATCH (DOUBLE):", )
                    print( "sbox #%d," % si, )
                    print( "lin.mask 0x%02x," % lin, )
                    print( "key 0x%02x=%r," % (k, chr(k)), )
                    print( "negated? %s," % bool(const1), )
                    # linear combination indexes (may be non-unique)
                    inds1 = vectors_rev[v1][:5]
                    inds2 = vectors_rev[v2][:5]
                    print( "indexes", "(%d and %d total)" % (len(vectors_rev[v1]), len(vectors_rev[v2])), inds1, inds2 )
                    print( )

                    g_candidates[si].add(k)
                    key_found = True

                    print( "   ", "   ", [divmod(v, 8) for v in vectors_rev[v1][:10]] )
                    print( "   ", "   ", [divmod(v, 8) for v in vectors_rev[v2][:10]] )
                    print( )

                    g_candidates[si].add(k)
                    n_matches[si] += 1
                    key_found = True

    if key_found:
        print( )
        print( "Key candidates found:" )
        for si, cands in enumerate(candidates):
            if cands:
                print( "S-Box #%d: %s" % (si, ",".join("0x%02x(%r)" % (c, chr(c)) for c in cands)) )
        print( )

    if key_found and STOP_ON_FIRST_MATCH:
        quit()


print("=================================")
print("")
print("Matches (by position):", n_matches)
print( "Key candidates found:" )
example = ""
for si, cands in enumerate(g_candidates):
    if cands:
        print( "S-Box #%d: %s" % (si, ",".join("0x%02x(%r)" % (c, chr(c)) for c in cands)) )
        for c in cands:
            break
        example += "%02x" % c
    else:
        example += "??"
print( )

print("Example:", example)
