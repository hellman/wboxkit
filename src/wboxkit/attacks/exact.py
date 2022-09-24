#!/usr/bin/env python3

import argparse
import importlib
import sys, os, string

from collections import defaultdict

from wboxkit.attacks.reader import Reader


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Apply "Exact Matching Attack" on pre-recorded traces.'
            #'Note: Changing the cipher may change the parameters',
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-h", "--help", action="store_true",
    )
    parser.add_argument(
        '-o', '--order', type=int, default=1,
        help="maximum attack order (1 or 2)",
    )
    parser.add_argument(
        '--cipher', default="AES",
        help="cipher to attack",
    )

    args, unknown = parser.parse_known_args()

    Reader.add_arguments(parser)

    cipher = args.cipher.lower().replace(".", "_")
    cipher_mod = importlib.import_module("." + cipher, package="wboxkit.ciphers")
    cipher_targets_cls = cipher_mod.Targets
    cipher_targets_cls.add_arguments(parser)

    if args.help:
        parser.print_help()
        quit()

    # ensure all args are known
    args = parser.parse_args()

    R = Reader.from_args(args)
    cipher_targets = cipher_targets_cls.from_args(args)

    # go from the end of the traces if we attack last S-Boxes ?
    REVERSE = False # not supported yet
    STOP_ON_FIRST_MATCH = 0
    ONE_CANDIDATE_PER_SBOX = 0

    # second order should break 1-st order linear masking
    ORDER = args.order
    if ORDER not in (1, 2):
        print("unsupported order", args.order, "(only 1 and 2 now)")
        quit()

    print( "Total traces:", R.ntraces, "of size", "%.1fK bits (%d)" % (R.trace_bytes / 1000.0, R.trace_bytes) )

    targets = cipher_targets.generate_targets(R)
    vector_ones = cipher_targets.vector_ones

    print( "Generated %d target vectors" % len(targets) )
    g_candidates = [set() for _ in range(16)]
    n_matches = [0] * 16

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

            if ORDER == 2:
                # shared in 2 shares
                for v1 in vectors_rev:
                    if v1 in (0, vector_ones):
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





if __name__ == '__main__':
    main()
