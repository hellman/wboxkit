from distutils.core import setup, Extension

fastcircuit = Extension(
    'fastcircuit',
    sources=['src/wboxkit/fastcircuit.c'],
)

setup(
    name='wboxkit',
    version='0.1.0',
    description='White-box Design & Cryptanalyis Kit',
    author='Aleksei Udovenko',
    author_email='aleksei@affine.group',
    url='https://github.com/hellman/wboxkit',
    ext_modules=[fastcircuit],
)
