from functools import reduce
from operator import xor

from circkit.transformers.core import CircuitTransformer
from circkit.array import Array


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
        raise NotImplementedError()

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

            self.prng.set_state(inputs)
            return Array(shares)

    def visit_INPUT(self, node):
        return self.result[node]

    def make_output(self, node, result):
        if self.decode_output:
            result = self.decode(result)
        super().make_output(node, result)


class ISW(MaskingTransformer):
    NAME_SUFFIX = "_ISW"

    def __init__(self, *args, order=2, **kwargs):
        n_shares = order + 1
        super().__init__(*args, n_shares=n_shares, **kwargs)

    def encode(self, s):
        x = [self.rand() for _ in range(self.n_shares-1)]
        x.append(reduce(xor, x) ^ s)
        return Array(x)

    def decode(self, x):
        return reduce(xor, x)

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



class BU18(MaskingTransformer):
    NAME_SUFFIX = "_ISW"

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
