from collections import deque
from functools import reduce

import random
from random import Random


class PRNG(object):
    n = NotImplemented # state size

    def __init__(self, clocks_initial=0, clocks_per_step=1):
        self.clocks_initial = int(clocks_initial)
        self.clocks_per_step = int(clocks_per_step)
        self.state = None

    def set_state(self, state, initialize=True):
        self.state = deque(state)
        self.n = len(self.state)
        if initialize:
            for _ in range(self.clocks_initial):
                self.clock()

    def step(self):
        for _ in range(self.clocks_per_step):
            res = self.clock()
        return res

    def clock(self):
        raise NotImplementedError()


class LFSR(PRNG):
    def __init__(self, taps, **kwargs):
        self.taps = tuple(map(int, taps))

        super().__init__(**kwargs)

    def clock(self):
        res = reduce(lambda a, b: a ^ b, [self.state[i] for i in self.taps])
        self.state.popleft()
        self.state.append(res)
        return res


class NFSR(PRNG):
    def __init__(self, taps, **kwargs):
        self.taps = tuple(tuple(map(int, mono)) for mono in taps)

        super().__init__(**kwargs)

    def clock(self):
        res = None
        for mono in self.taps:
            mono = reduce(
                lambda a, b: a & b,
                [self.state[i] for i in mono],
                1,
            )
            res = mono if res is None else (res ^ mono)

        self.state.popleft()
        self.state.append(res)
        return res


class Pool(PRNG):
    def __init__(self, prng, seed=None, n=1000):
        self.prng = prng
        self.n = int(n)

        if seed is None:
            self.random = random
        else:
            self.random = Random()
            self.random.seed(seed)

    def set_state(self, state):
        self.prng.set_state(state)
        self.state = tuple(self.prng.step() for _ in range(self.n))

    def step(self):
        return self.random.choice(self.state)
