import os
from collections import deque
from pathlib import Path


class Reader(object):
    TRACE_FILENAME_FORMAT = "%04d.bin"
    PLAINTEXT_FILENAME_FORMAT = "%04d.pt"
    CIPHERTEXT_FILENAME_FORMAT = "%04d.ct"

    @classmethod
    def from_argparser(
        cls,
        parser,
        default_n_traces=100,
        default_window=2048,
    ):
        parser.add_argument(
            'trace_dir', type=Path,
            help="path to directory with trace/plaintext/ciphertext files")

        parser.add_argument(
            '-T', '--n-traces', type=int, default=default_n_traces,
            help="number of traces to use in the attack"
        )
        parser.add_argument(
            '-w', '--window', type=int, default=default_window,
            help="sliding window size"
        )
        parser.add_argument(
            '-s', '--step', type=int, default=0,
            help="sliding window step (default: window/4)",
        )
        # parser.add_argument(
        #     '--reverse', action="store_true",
        #     help="attack order (1 or 2)",
        # )

        args, unknown = parser.parse_known_args()

        if args.step > args.window:
            print("step larger than the window size, reducing to window/4")
            args.step = args.window // 4
        if args.step <= 0:
            args.step = args.window // 4
        args.step = max(1, args.step)

        REVERSE=False
        return cls(
            ntraces=args.n_traces,
            window=args.window,
            step=args.step,
            packed=True,
            reverse=REVERSE,
            dir=args.trace_dir,
        )

    def __init__(self, ntraces, window, step=None,
                       packed=True, reverse=False, dir="./traces"):

        dir = Path(dir)
        self.packed = packed

        self.pts = []
        self.cts = []
        self.fds = []

        self.trace_bytes = None
        self.ntraces = int(ntraces)
        self.window = int(window)

        assert self.ntraces >= 1
        for i in range(self.ntraces):
            f_trace = dir / (self.TRACE_FILENAME_FORMAT % i)
            f_pt = dir / (self.PLAINTEXT_FILENAME_FORMAT % i)
            f_ct = dir / (self.CIPHERTEXT_FILENAME_FORMAT % i)

            self.pts.append(open(f_pt, "rb").read())
            self.cts.append(open(f_ct, "rb").read())

            new_size = os.stat(f_trace).st_size
            if self.trace_bytes is None:
                self.trace_bytes = new_size
            assert self.trace_bytes == new_size, "Trace files must have the same size"

            self.fds.append(open(f_trace, "rb"))

        self.reverse = reverse
        if reverse:
            raise NotImplementedError("Not supported yet")

        if step is None:
            step = window
        assert 0 < step <= window

        if self.packed:
            # round up to multiple of 8
            window += (8 - window % 8) % 8
            step += (8 - step % 8) % 8
            self.window_bytes = window // 8
            self.step_bytes = step // 8
        else:
            self.window_bytes = window
            self.step_bytes = step

        self.window_bytes = min(self.window_bytes, self.trace_bytes)
        self.step_bytes = min(self.step_bytes, self.trace_bytes)

        # may be ceil? not accurate!
        self.num_windows = (self.trace_bytes - self.window_bytes + self.step_bytes - 1) // self.step_bytes + 1

        # not sure if working with longs is faster than with arrays
        # or some other structure, may be even makes sense to write C backend

    def __iter__(self):
        self.vectors = deque()
        self.offset = 0
        self.advance(self.window_bytes)
        for v in self.new_vectors:
            self.vectors.append(v)
        yield self.vectors

        while True:
            if self.offset + self.window_bytes >= self.trace_bytes:
                # already covered the whole trace
                return

            self.advance(self.step_bytes)
            for v in self.new_vectors:
                self.vectors.append(v)
                self.vectors.popleft()
            self.offset += self.step_bytes

            yield self.vectors


    def advance(self, num_bytes):
        self.new_vectors = [0] * (num_bytes * 8)
        for fd in self.fds:
            data = fd.read(num_bytes)
            self.process_window(data)
        self.new_vectors = self.new_vectors[:len(data)*8]

    def process_window(self, data):
        vectors = self.new_vectors
        if not self.packed:
            # 1 bit in byte
            for i, b in enumerate(data):
                val = b & 1
                vectors[i] = (vectors[i] << 1) | val
            assert b in "\x00\x01", "sure not packed?"
        else:
            # 8 bits in byte (packed)
            for i, b in enumerate(data):
                b = b
                for j in range(8):
                    id = (i << 3) | j
                    bit = (b >> (7 - j)) & 1
                    vectors[id] = (vectors[id] << 1) | bit
