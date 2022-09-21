from functools import reduce
from operator import xor
from queue import PriorityQueue

import logging

from circkit.transformers.core import CircuitTransformer
from circkit.array import Array

from wboxkit.containers import Rect


log = logging.getLogger(__name__)


def xorlist(lst):
    return reduce(xor, lst, 0)


class MaskingTransformer(CircuitTransformer):
    START_FROM_VARS = True  # ensure all INPUTS are processed first

    def __init__(self, prng=None, n_shares=2, encode_input=True, decode_output=True):
        """rand() -> random bit"""
        if prng is None:
            self.prng = None
        else:
            self.prng = prng

        self.n_shares = int(n_shares)
        assert n_shares >= 1  # maybe 1 is useful for debugging purposes

        self.encode_input = encode_input
        self.decode_output = decode_output

    def rand(self):
        if self.prng is None:
            return self.target_circuit.RND()()
        return self.prng.step()

    def encode(self, x):
        raise NotImplementedError()

    def decode(self, x):
        raise NotImplementedError()

    def refresh(self, x):
        raise NotImplementedError()

    def visit_generic(self, node, *args):
        raise NotImplementedError(f"visiting {node}")

    def __repr__(self):
        return (
            "<MaskingScheme:%s n_shares=%d prng=%r>"
            % (type(self).__name__, self.n_shares, self.prng)
        )

    def before_transform(self, circuit, **kwargs):
        super().before_transform(circuit, **kwargs)

        # create input vars beforehand to initialize the prng
        if self.encode_input:
            inputs = []
            for node in circuit.inputs:
                new_node = super().visit_generic(node)
                inputs.append(new_node)

            if self.prng is not None:
                self.prng.set_state(inputs)

            for old_node, new_node in zip(circuit.inputs, inputs):
                self.result[old_node] = self.encode(new_node)
        else:
            inputs = []
            for node in circuit.inputs:
                shares = []
                for i in range(self.n_shares):
                    new_name = f"{node.operation.name}_share{i}"
                    x = self.target_circuit.add_input(new_name)
                    shares.append(x)
                self.result[node] = shares
                inputs.extend(shares)

            if self.prng is not None:
                self.prng.set_state(inputs)

    def visit_INPUT(self, node):
        return self.result[node]

    def make_output(self, node, result):
        if self.decode_output:
            result = self.decode(result)
        super().make_output(node, result)


class ISW(MaskingTransformer):
    """Private Circuits [ISW03]"""
    NAME_SUFFIX = "_ISW"

    def __init__(self, *args, order=2, **kwargs):
        n_shares = order + 1
        super().__init__(*args, n_shares=n_shares, **kwargs)

    def encode(self, s):
        x = [self.rand() for _ in range(self.n_shares-1)]
        x.append(xorlist(x) ^ s)
        return Array(x)

    def decode(self, x):
        return xorlist(x)

    def visit_XOR(self, node, x, y):
        return x ^ y

    def visit_AND(self, node, x, y):
        r = [[0] * self.n_shares for _ in range(self.n_shares)]
        for i in range(self.n_shares):
            for j in range(i+1, self.n_shares):
                r[i][j] = self.rand()
                r[j][i] = r[i][j] ^ x[i]&y[j] ^ x[j]&y[i]

        z = x & y
        for i in range(self.n_shares):
            for j in range(self.n_shares):
                if i != j:
                    z[i] = z[i] ^ r[i][j]
        return z

    def visit_NOT(self, node, x):
        x = Array(x)
        x[0] = 1^x[0]
        return x



class MINQ(MaskingTransformer):
    """MINimalist Quadratic Masking [BU18]"""
    NAME_SUFFIX = "_MINQ"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, n_shares=3, **kwargs)

    def encode(self, s):
        a = self.rand()
        b = self.rand()
        c = (a & b) ^ s
        return a, b, c

    def decode(self, x):
        return (x[0] & x[1]) ^ x[2]

    def rand3(self):
        return (self.rand(), self.rand(), self.rand())

    def refresh(self, x, rs=None):
        a, b, c = x
        if rs is None:
            rs = self.rand3()
        ra, rb, rc = rs
        ma = ra & (b ^ rc)
        mb = rb & (a ^ rc)
        rmul = (ra ^ rc) & (rb ^ rc)
        rc ^= ma ^ mb ^ rmul
        a ^= ra
        b ^= rb
        c ^= rc
        return a, b, c

    def visit_XOR(self, node, x, y):
        rxs = ra, rb, rc = self.rand3()
        rys = rd, re, rf = self.rand3()
        a, b, c = self.refresh(x, rs=rxs)
        d, e, f = self.refresh(y, rs=rys)
        x = a ^ d
        y = b ^ e
        ae = a & e
        bd = b & d
        z = c ^ f ^ ae ^ bd
        return x, y, z

    def visit_AND(self, node, x, y):
        rxs = ra, rb, rc = self.rand3()
        rys = rd, re, rf = self.rand3()
        a, b, c = self.refresh(x, rs=rxs)
        d, e, f = self.refresh(y, rs=rys)

        ma = (b & f) ^ (rc & e)
        md = (c & e) ^ (rf & b)
        x = rf ^ (a & e)
        y = rc ^ (b & d)
        ama = a & ma
        dmd = d & md
        rcrf = rc & rf
        cf = c & f
        z = ama ^ dmd ^ rcrf ^ cf
        return x, y, z

    def visit_NOT(self, node, x):
        return x[0], x[1], ~x[2]


class QuadLin(MaskingTransformer):
    """Quadratic Monomial + Linear shares [Seker,Eisenbarth,Liśkiewicz 2021]"""

    NAME_SUFFIX = "_QuadLin"

    def __init__(self, *args, n_linear=2, **kwargs):
        self.n_linear = int(n_linear)
        super().__init__(*args, n_shares=2 + n_linear, **kwargs)

    def encode(self, s):
        tx0 = self.rand()
        tx1 = self.rand()
        lins = [self.rand() for _ in range(self.n_linear-1)]
        lins.append(xorlist(lins) ^ (tx0 & tx1) ^ s)
        return tx0, tx1, Array(lins)

    def decode(self, x):
        return (x[0] & x[1]) ^ xorlist(x[2])

    def refresh(self, x):
        tx0, tx1, lins = x

        tr0 = self.rand()  # tilde r0
        tr1 = self.rand()  # tilde r1

        tx0 ^= tr0
        tx1 ^= tr1

        x = list(lins)
        for i in range(len(x)):
            for j in range(i + 1, len(x)):
                r = self.rand()
                x[i] ^= r
                x[j] ^= r

        r0 = self.rand()
        W = (tr0 & (tx1 ^ r0)) ^ ((tr1 & (tx0 ^ r0)))
        R = ((tr0 ^ r0) & (tr1 ^ r0)) ^ r0
        x[-1] ^= W ^ R
        return tx0, tx1, Array(x)

    def visit_XOR(self, node, x, y):
        tx0, tx1, x = self.refresh(x)
        ty0, ty1, y = self.refresh(y)

        tz0 = tx0 ^ ty0
        tz1 = tx1 ^ ty1

        z = x ^ y
        U = (tx0 & ty1) ^ (tx1 & ty0)
        z[-1] ^= U
        return tz0, tz1, z

    def visit_AND(self, node, x, y):
        tx0, tx1, x = self.refresh(x)
        ty0, ty1, y = self.refresh(y)
        n = len(x)

        r0  = Array(self.rand() for _ in range(n))
        r1  = Array(self.rand() for _ in range(n))

        tz0 = (tx0 & ty1) ^ xorlist(r0)
        tz1 = (tx1 & ty0) ^ xorlist(r1)

        r = {}
        for i in range(n+1):
            ii = i - 1
            for j in range(i+1, n+1):
                jj = j - 1
                if i == 0:

                    r[j,0] = (
                        (tx1 & ((tx0&y[jj]) ^ (r0[jj]&ty0)))
                        ^ (ty1 & ((ty0&x[jj]) ^ (r1[jj]&tx0)))
                        ^ (r1[jj]  & xorlist(r0))
                    )
                else:
                    r[i,j] = self.rand()
                    r[j,i] = (r[i,j] ^ (x[ii]&y[jj])) ^ (x[jj]&y[ii])

        z = [None] * n
        for i in range(1, n+1):
            ii = i - 1
            z[ii] = x[ii] & y[ii]
            for j in range(n+1):
                if j != i:
                    z[ii] ^= r[i,j]
        return tz0, tz1, Array(z)

    def visit_NOT(self, node, x):
        lins = Array(x[2])
        lins[-1] = 1 ^ lins[-1]
        return x[0], x[1], lins



class DumShuf(MaskingTransformer):
    """Dummy Shuffling [BU21]"""
    NAME_SUFFIX = "_DumShuf"
    EPSILON = 1e-9

    def __init__(self, *args, n_shares=2, max_bias=1/8.0, **kwargs):
        assert n_shares >= 1
        super().__init__(*args, n_shares=n_shares, **kwargs)

        self.n_dummy = int(self.n_shares) - 1
        if self.n_dummy == 0:
            log.warning(f"DummyLESS shuffling (n_shares={n_shares})")

        self.max_bias = float(max_bias)
        assert 0 < self.max_bias <= 1

        self.refresh = None

    def before_transform(self, circuit, **kwargs):
        super().before_transform(circuit, **kwargs)

        # create input vars beforehand to initialize the prng
        if self.encode_input:
            self.refresh = {}

            inputs = []
            for node in circuit.inputs:
                new_node = super(MaskingTransformer, self).visit_generic(node)
                inputs.append(new_node)

            self.prng.set_state(inputs)

            targets = []
            shuf = []
            for old_node, new_node in zip(circuit.inputs, inputs):
                targets.append((self.result, old_node))
                shuf.append(self.encode(new_node))

            for old_node in circuit:
                if old_node.is_AND():
                    targets.append((self.refresh, old_node))
                    shuf.append(self.encode(0))

            self.flags = self.create_shuffle()
            shuf = list(map(Array, Rect.from_rect(shuf).transpose()))
            shuf = self.shuffle(shuf, flags=self.flags)
            shuf = list(map(Array, Rect.from_rect(shuf).transpose()))
            for (target, node), shares in zip(targets, shuf):
                target[node] = shares

        else:
            raise NotImplementedError()

    def visit_all(self, circuit):
        super().visit_all(circuit)

        if self.decode_output:
            shuf = []
            for node in circuit.outputs:
                shuf.append(self.result[node])

            shuf = list(map(Array, Rect.from_rect(shuf).transpose()))
            shuf = self.unshuffle(shuf, flags=self.flags)
            shuf = list(map(Array, Rect.from_rect(shuf).transpose()))

            for node, shares in zip(circuit.outputs, shuf):
                self.result[node] = shares

    def encode(self, s):
        # here we create dummy slots
        # but not shuffle yet
        x = [s] + [self.rand() for _ in range(self.n_shares-1)]
        return Array(x)

    def decode(self, x):
        return x[0]

    def create_shuffle(self):
        flags = []

        cur_ver = {i: 0 for i in range(self.n_shares)}

        # -prob, index, version
        pq_max = PriorityQueue()
        pq_max.put((-1.0, 0, 0))

        #-prob, index, version
        pq_min = PriorityQueue()
        for i in range(1, self.n_shares):
            pq_min.put((0.0, i, 0))

        # TODO: update algo to ensure bias in both directions is ok
        # (currently one position can be prob=0.0 if it's prob can split
        # across other positions without overflowing the limit)
        goal = 1 / self.n_shares
        ubound = goal + self.max_bias
        lbound = goal - self.max_bias
        while True:
            assert not pq_max.empty()
            src_prob, src, src_ver = pq_max.get()
            src_prob = -src_prob
            if src_ver != cur_ver[src]:
                continue

            found = 0
            while not pq_min.empty():
                dst_prob, dst, dst_ver = pq_min.get()
                #print("try", dst, dst_prob)
                if dst_ver != cur_ver[dst]:
                    continue
                if src == dst:
                    continue
                if abs(src_prob - dst_prob) < self.EPSILON:
                    continue

                found = 1
                break

            if (lbound <= dst_prob + self.EPSILON
                and src_prob <= ubound + self.EPSILON):
                log.info(
                    "finished with probs"
                    f" lb:{lbound:.3f}"
                    f" <= min:{dst_prob:.3f}"
                    f" <= goal:{goal:.3f}"
                    f" <= max:{src_prob:.3f}"
                    f" <= ub:{ubound:.3f}"
                )
                break

            assert found

            prob = (src_prob + dst_prob) / 2
            log.info(f"swap {src} {dst}: {src_prob:.3f} {dst_prob:.3f} -> {prob:.3f}")

            flag = self.rand()
            flags.append((flag, src, dst))

            ver = max(src_ver, dst_ver) + 1

            cur_ver[src] = ver
            cur_ver[dst] = ver

            pq_max.put((-prob, src, ver))
            pq_max.put((-prob, dst, ver))

            pq_min.put((prob, src, ver))
            pq_min.put((prob, dst, ver))
        return flags

    def shuffle(self, xs, flags):
        xs = list(xs)
        n = len(xs[0])
        for flag, i, j in flags:
            flag_vec = Array([flag]*n)
            xs[i], xs[j] = self.cswap(xs[i], xs[j], flag=flag_vec)
        return xs

    def unshuffle(self, xs, flags):
        xs = list(xs)
        n = len(xs[0])
        for flag, i, j in reversed(flags):
            flag_vec = Array([flag]*n)
            xs[i], xs[j] = self.cswap(xs[i], xs[j], flag=flag_vec)
        return xs

    def cswap(self, x, y, flag):
        dxy = flag & (x ^ y)
        return (dxy ^ y, dxy ^ x)

    def visit_XOR(self, node, x, y):
        return x ^ y

    def visit_NOT(self, node, x):
        return ~x

    def visit_AND(self, node, x, y):
        return (x & y) ^ self.refresh[node]
