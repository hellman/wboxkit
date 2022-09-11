from collections import deque
from functools import reduce

import random
from random import Random


class PRNG(object):
    n = NotImplemented # state size

    def __init__(self, state, clocks_initial=0, clocks_per_step=1):
        self.n = len(state)
        self.set_state(state)

        self.clocks_per_step = int(clocks_per_step)

        for _ in range(clocks_initial):
            self.clock()

    def set_state(self, state):
        self.state = deque(state)
        assert len(self.state) == self.n

    def step(self):
        for _ in range(self.clocks_per_step):
            res = self.clock()
        return res

    def clock(self):
        raise NotImplementedError()


class LFSR(PRNG):
    def __init__(self, taps, state, **kwargs):
        n = len(state)
        assert all(0 <= tap < n for tap in taps)
        self.taps = tuple(map(int, taps))

        super().__init__(state, **kwargs)

    def clock(self):
        res = reduce(lambda a, b: a ^ b, [self.state[i] for i in self.taps])
        self.state.popleft()
        self.state.append(res)
        return res


class NFSR(PRNG):
    def __init__(self, taps, ntaps, state, **kwargs):
        n = len(state)
        assert all(0 <= tap < n for tap in taps)
        assert all(0 <= tap < n for mono in ntaps for tap in mono)
        assert 0 in taps
        self.taps = tuple(map(int, taps))
        self.ntaps = tuple(tuple(map(int, mono)) for mono in ntaps)

        super().__init__(state, **kwargs)

    def clock(self):
        res = reduce(
            lambda a, b: a ^ b,
            [self.state[i] for i in self.taps]
        )
        for mono in self.ntaps:
            res ^= reduce(
                lambda a, b: a & b,
                [self.state[i] for i in mono]
            )

        self.state.popleft()
        self.state.append(res)
        return res


class Pool(PRNG):
    def __init__(self, prng, seed=None, n=1000):
        self.prng = prng
        self.n = int(n)
        self.state = tuple(prng.step() for _ in range(self.n))

        if seed is None:
            self.random = random
        else:
            self.random = Random()

    def step(self):
        return self.random.choice(self.state)
