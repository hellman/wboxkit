# `wboxkit`: White-box Cryptography Design and Analysis kit

This project is a successor of the previous [`cryptolu/whitebox`](https://github.com/cryptolu/whitebox/tree/master/synthesis) framework proposed at the [WhibOx 2019](https://www.cryptoexperts.com/whibox2019/) workshop, which was written in Python 2 and used custom Boolean circuits. The new version (this repo) is rewritten for Python 3 and also is based on the recent more generic circuit framework [circkit](https://github.com/cryptoexperts/circkit). It also brings improved interfaces and some [tutorials](./tutorials/) (first presented at the [CHES 2022 White-box Cryptography tutorial](https://ches.iacr.org/2022/tutorials.php), see (outdated) [repo](https://github.com/hellman/ches2022wbc)).

The primary use-case of `wboxkit` is research and experiments on white-box cryptography implementations. Currently, it has attacks/circuit only for AES-128, but general countermeasures (ISW03 linear masking, BU18 nonlinear masking, SEL21 nonlinear masking, BU21 dummy shuffling).

It is not yet documented, but the examples in the tutorials should be sufficient for many purposes.

## Installation

It can be installed from PyPI using pip (a C extension requires a compiler and the python-dev package). It is recommended to use [PyPy3](https://www.pypy.org/download.html) which offers much better performance.

```sh
pip install wboxkit
# or
pypy -m pip install wboxkit
```

For the LDA (linear algebraic / linear decoding attack) to work, it has to be installed with [SageMath](https://www.sagemath.org/):

```sh
sage -pip install wboxkit
sage -sh
$ wboxkit.lda traces/
```

## Scripts

The package installs a few scripts:

- `wboxkit.trace` records a set of computational traces of a given Boolean circuit (serialized in a file).
- `wboxkit.exact` performs the exact matching attack.
- `wboxkit.lda` performs the linear decoding / linear algebraic attack (LDA).


## Tutorials

- [Tutorial 1 - Circuits](./tutorials/Tutorial%201%20-%20Circuits.ipynb)
- [Tutorial 2 - Countermeasures](./tutorials/Tutorial%202%20-%20Countermeasures.ipynb)
- [Tutorial 3 - Tracing](./tutorials/Tutorial%203%20-%20Tracing.ipynb)
- [Tutorial 4 - Attacks](./tutorials/Tutorial%204%20-%20Attacks.ipynb)

See also `circkit` [documentation/tutorials](https://circkit.readthedocs.io/en/latest/).