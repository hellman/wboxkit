#!/usr/bin/env sage -python
#-*- coding:utf-8 -*-

from sage.all import Integer, vector, GF, matrix

import argparse
import pathlib
import sys, os, string

from random import sample
from itertools import product

from sbox import sbox, rsbox
from reader import Reader


parser = argparse.ArgumentParser(
    description='Apply "Linear Algebraic Attack (LDA)" on pre-recorded traces.',
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
    help="sliding window step"
)
parser.add_argument(
    '--masks', default="1,2,4,8,16,32,64,128",
    help=(
        "linear masks to consider"
        " (comma separated ints, or 'all', or 'random16', 'random32')"
    )
)
parser.add_argument(
    '--pos', default="0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
    help="byte positions to attack",
)

args = parser.parse_args()

#== Configuration

# go from the end of the traces if we attack last S-Boxes ?
REVERSE = False # not supported yet

if args.window >= args.n_traces - 10:
    print("#traces too close to window size w (small), increasing to w+50")
    args.n_traces = args.window + 50

if args.step > args.window:
    print("step s larger than the window size w, reducing to window/4")
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



def tobin(x, n):
    return tuple(map(int, bin(x).lstrip("0b").rjust(n, "0")))

def scalar_bin(a, b):
    return int(Integer(a & b).popcount())

MASK = 2**R.ntraces - 1
VECMASK = vector(GF(2), [1] * R.ntraces)

print( "Total traces:", R.ntraces, "of size", "%.1fK bits (%d)" % (R.trace_bytes / 1000.0, R.trace_bytes))

#== Generate predicted vectors from plaintext/ciphertext and key guess

targets = []
for si, lin, k in product(BYTE_INDICES, LINS, KS):
    target = []
    for p, c in zip(R.pts, R.cts):
        if k is None:
            if CT_SIDE:
                x = c[si]
            else:
                x = p[si]
        else:
            if CT_SIDE:
                x = c[si]
                x = rsbox[x ^ k]
            else:
                x = p[si]
                x = sbox[x ^ k]
        target.append(scalar_bin(x, lin))
    assert len(target) == R.ntraces
    target = vector(GF(2), target)
    targets.append((target, (si, lin, k, 0)))
    targets.append((target + VECMASK, (si, lin, k, 1)))

print( "Generated %d target vectors" % len(targets))

target_mat = matrix(GF(2), [target for target, kinfo in targets])

#== Read traces and analyze
candidates = [set() for _ in range(16)]
n_matches = [0 for _ in range(16)]
g_candidates = [set() for _ in range(16)]
for i_window, vectors in enumerate(R):
    print( "Window %d" % (i_window+1), "/", R.num_windows,)

    print( "offset %d-%d (of %d)" % (R.offset*8, R.offset*8 + len(vectors), R.trace_bytes*8))
    print( "   ", len(vectors), "vectors")

    vectors_rev = set(vectors)
    print( "   ", len(vectors_rev), "unique vectors")
    print( "   ", len(targets), "target vectors")

    key_found = False

    columns = [list(tobin(vec, R.ntraces)) for vec in vectors_rev if vec not in (0, MASK)]
    mat = matrix(GF(2), columns)

    # trick to use kernel of M for quick verification of solution
    parity_checker = mat.right_kernel().matrix().transpose()
    check = target_mat * parity_checker
    check = map(bool, check.rows())
    for parity, (target, kinfo) in zip(check, targets):
        if parity:
            continue

        # can be done more efficiently using LU factors of mat (shared with left_kernel)
        # but happens only when the key is found
        # so optimization is not necessary
        sol = mat.solve_left(target)
        # assert sol * mat == target

        si, lin, k, const1 = kinfo
        print( "MATCH:",)
        print( "sbox #%d," % si,)
        print( "lin.mask 0x%02x," % lin,)
        print( "key 0x%02x=%r," % (k, chr(k)),)
        print( "negated? %s," % bool(const1),)
        # linear combination indexes (may be non-unique)
        inds = [R.offset + i for i, take in enumerate(sol) if take]
        print( "indexes", "%d...%d (distance %d)" % (min(inds), max(inds), max(inds)-min(inds)), inds,)
        print()

        candidates[si].add(k)
        g_candidates[si].add(k)
        n_matches[si] += 1
        key_found = True

    if key_found:
        print()
        print( "Key candidates found:")
        for si, cands in enumerate(candidates):
            if cands:
                print( "S-Box #%d: %s" % (si, ",".join("0x%02x(%r)" % (c, chr(c)) for c in cands)))
        print()

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
