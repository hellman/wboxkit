#!/usr/bin/env sage -python
#-*- coding:utf-8 -*-

from sage.all import Integer, vector, GF, matrix

import argparse
import importlib
import sys, os, string

from collections import defaultdict

from bitarray import frozenbitarray

from wboxkit.attacks.reader import Reader


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Apply "Linear Algebraic / Linear Decoding Attack (LDA)" on pre-recorded traces.'
            #'Note: Changing the cipher may change the parameters',
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-h", "--help", action="store_true",
    )
    # parser.add_argument(
    #     '-o', '--order', type=int, default=1,
    #     help="maximum attack order (1 or 2)",
    # )
    parser.add_argument(
        '--cipher', default="AES",
        help="cipher to attack",
    )

    args, unknown = parser.parse_known_args()

    Reader.add_arguments(
        parser,
        default_n_traces=256 + 50,
        default_window=256,
    )

    cipher = args.cipher.lower().replace(".", "_")
    cipher_mod = importlib.import_module("." + cipher, package="wboxkit.ciphers")
    cipher_targets_cls = cipher_mod.Targets
    cipher_targets_cls.add_arguments(parser)

    if args.help:
        parser.print_help()
        quit()

    # ensure all args are known
    args = parser.parse_args()

    R = Reader.from_args(args, as_vectors=False)
    cipher_targets = cipher_targets_cls.from_args(args)

    if R.ntraces <= R.window:
        print(
            "error: ntraces <= window (no redundancy):",
            R.ntraces, "<=", R.window,
        )
        quit()

    # go from the end of the traces if we attack last S-Boxes ?
    REVERSE = False # not supported yet
    STOP_ON_FIRST_MATCH = 0
    ONE_CANDIDATE_PER_SBOX = 0

    # # second order should break 1-st order linear masking
    ORDER = 1
    # ORDER = args.order
    # if ORDER not in (1, 2):
    #     print("unsupported order", args.order, "(only 1 and 2 now)")
    #     quit()


    print( "Total traces:", R.ntraces, "of size", "%.1fK bits (%d)" % (R.trace_bytes / 1000.0, R.trace_bytes) )

    targets = cipher_targets.generate_targets(R)

    print( "Generated %d target vectors" % len(targets) )

    vector_ones = frozenbitarray([1] * R.ntraces)

    #== Read traces and analyze
    candidates = [set() for _ in range(16)]
    n_matches = [0 for _ in range(16)]
    for i_window, vectors in enumerate(R):
        print( "Window %d" % (i_window+1), "/", R.num_windows,)

        print( "offset %d-%d (of %d)" % (R.offset*8, R.offset*8 + len(vectors), R.trace_bytes*8))
        print( "   ", len(vectors), "vectors")

        vectors_rev = set(vectors)
        print( "   ", len(vectors_rev), "unique vectors")
        print( "   ", len(targets), "target vectors")

        key_found = False

        columns = [
            vec for vec in vectors_rev
            if vec.count(0) and vec.count(1)
        ]
        if not columns:
            continue

        # we now need sage only for right kernel
        # and solve_left kinfo recovery below...
        trace_matrix = matrix(GF(2), columns)

        parity_checks = trace_matrix.right_kernel().matrix()
        assert parity_checks.nrows() and parity_checks.ncols()  # regression
        parity_checks = [frozenbitarray(row) for row in parity_checks]

        # optimized implementation : check bit-by-bit, O(n^3 + nk)
        for target, kinfo in targets:
            match = True
            nm = 0
            for row in parity_checks:
                #if row * target:
                if (row & target).count(1) & 1:
                    match = False
                    break
                nm += 1
            if not match:
                continue

            # can be done more efficiently using LU factors of mat (shared with left_kernel)
            # but happens only when the key is found
            # so optimization is not necessary
            sol = trace_matrix.solve_left(vector(GF(2), target))
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
    for si, cands in enumerate(candidates):
        if cands:
            print( "S-Box #%d: %s" % (si, ",".join("0x%02x(%r)" % (c, chr(c)) for c in cands)) )
            for c in cands:
                break
            example += "%02x" % c
        else:
            example += "??"
    print( )

    print("Example:", example)


def tobin(x, n):
    return tuple(map(int, bin(x).lstrip("0b").rjust(n, "0")))

def scalar_bin(a, b):
    return int(Integer(a & b).popcount())


if __name__ == '__main__':
    main()
