from random import randrange, sample
from itertools import product


class AESTargets:
    from wboxkit.ciphers.aes.aes import sbox as SBOX
    from wboxkit.ciphers.aes.aes import rsbox as iSBOX

    @classmethod
    def from_argparser(cls, parser):
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

        args, unknown = parser.parse_known_args()

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
        )

    def __init__(self, indexes, masks):
        self.indexes = tuple(map(int, indexes))
        self.masks = tuple(map(int, masks))
        self.charset = range(256)


    def generate_targets(self, reader):
        """Generate predicted vectors from plaintext/ciphertext and key guess"""
        sbox, isbox = self.SBOX, self.iSBOX
        ct_side = reader.reverse

        ones = self.vector_ones = 2**reader.ntraces - 1

        targets = []
        for si, lin, k in product(self.indexes, self.masks, self.charset):
            target = 0
            for p, c in zip(reader.pts, reader.cts):
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
                target = (target << 1) | scalar_bin(x, lin)

            targets.append((target, (si, lin, k, 0)))
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
