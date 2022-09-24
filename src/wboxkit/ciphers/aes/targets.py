from random import randrange, sample
from itertools import product

from bitarray import frozenbitarray, bitarray


class AESTargets:
    from wboxkit.ciphers.aes.aes import sbox as SBOX
    from wboxkit.ciphers.aes.aes import rsbox as iSBOX

    @classmethod
    def add_arguments(cls, parser):
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

    @classmethod
    def from_args(cls, args, as_vectors=False):
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

        print("Using linear masks:", LINS)
        return cls(
            indexes=BYTE_INDICES,
            masks=LINS,
            as_vectors=as_vectors,
        )

    def __init__(self, indexes, masks, as_vectors=False):
        self.indexes = tuple(map(int, indexes))
        self.masks = tuple(map(int, masks))
        self.charset = range(256)

        self.as_vectors = as_vectors
        if as_vectors:
            from sage.all import vector, GF

            self.cls_array = lambda v: vector(GF(2), v)
            self.cls_array_freeze = lambda v: v.set_immutable() or v
        else:
            self.cls_array = bitarray
            self.cls_array_freeze = frozenbitarray

    def generate_targets(self, reader):
        """Generate predicted vectors from plaintext/ciphertext and key guess"""
        sbox, isbox = self.SBOX, self.iSBOX
        ct_side = reader.reverse

        ones = self.cls_array([1] * reader.ntraces)

        self.vector_ones = ones = self.cls_array_freeze(ones)

        scalar_map = [
            [scalar_bin(x, lin) for x in range(256)]
            for lin in range(256)
        ]

        targets = []
        for si, lin, k in product(self.indexes, self.masks, self.charset):
            target = self.cls_array(reader.ntraces)
            scalar_lin = scalar_map[lin]
            for itrace, (p, c) in enumerate(zip(reader.pts, reader.cts)):
                if k is None:
                    if ct_side:
                        x = c[si]
                    else:
                        x = p[si]
                else:
                    if ct_side:
                        x = c[si]
                        x = isbox[x ^ k]
                    else:
                        x = p[si]
                        x = sbox[x ^ k]
                #target[itrace] = scalar_bin(x, lin)
                target[itrace] = scalar_lin[x]

            target = self.cls_array_freeze(target)
            targets.append((target, (si, lin, k, 0)))
            if self.as_vectors:
                targets.append((target + ones, (si, lin, k, 1)))
            else:
                targets.append((target ^ ones, (si, lin, k, 1)))
        return targets


def scalar_bin(a, b):
    v = a & b
    res = 0
    while v:
        res ^= v & 1
        v >>= 1
    return res


Targets = AESTargets
