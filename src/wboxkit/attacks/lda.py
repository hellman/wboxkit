#!/usr/bin/env sage -python
#-*- coding:utf-8 -*-

from sage.all import Integer, vector, GF, matrix

import argparse
import importlib
import sys, os, string

from collections import defaultdict

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
    cipher = args.cipher.lower().replace(".", "_")
    cipher_mod = importlib.import_module("." + cipher, package="wboxkit.ciphers")
    cipher_targets = cipher_mod.Targets.from_argparser(parser)

    R = Reader.from_argparser(
        parser,
        default_n_traces=256 + 50,
        default_window=256,
    )
    if R.ntraces <= R.window:
        print(
            "error: ntraces <= window (no redundancy):",
            R.ntraces, "<=", R.window,
        )
        quit()

    if args.help:
        parser.print_help()
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
    targets = [
        (vector(GF(2), tobin(t, R.ntraces)), kinfo)
        for t, kinfo in targets
    ]
    target_mat = matrix(GF(2), [t for t, kinfo in targets])
    vector_ones = vector(GF(2), [1] * R.ntraces)

    print( "Generated %d target vectors" % len(targets) )
    g_candidates = [set() for _ in range(16)]
    n_matches = [0] * 16

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
            list(tobin(vec, R.ntraces))
            for vec in vectors_rev
            if vec not in (0, vector_ones)
        ]
        mat = matrix(GF(2), columns)

        # trick to use kernel of M for quick verification of solution
        parity_checker = mat.right_kernel().matrix().transpose()
        assert parity_checker.nrows() and parity_checker.ncols()
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
