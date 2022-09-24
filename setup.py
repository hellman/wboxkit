# setup.py based on https://github.com/himbeles/ctypes-example
# https://stackoverflow.com/questions/4529555/building-a-ctypes-based-c-library-with-distutils


from setuptools import setup, Extension, find_packages
from distutils.command.build_ext import build_ext as build_ext_orig


class CTypesExtension(Extension):
    pass


class build_ext(build_ext_orig):

    def build_extension(self, ext):
        self._ctypes = isinstance(ext, CTypesExtension)
        return super().build_extension(ext)

    def get_export_symbols(self, ext):
        if self._ctypes:
            return ext.export_symbols
        return super().get_export_symbols(ext)

    def get_ext_filename(self, ext_name):
        if self._ctypes:
            return ext_name + '.so'
        return super().get_ext_filename(ext_name)


setup(
    name='wboxkit',
    version='0.4.3',
    description='White-box Design & Cryptanalyis Kit',
    keywords='white-box cryptography design cryptanalyis circuits',

    author='Aleksei Udovenko',
    author_email='aleksei@affine.group',
    url='https://github.com/hellman/wboxkit',
    license='MIT',

    packages=find_packages("src"),
    package_dir={'': 'src'},

    python_requires='>=3',
    install_requires=['bitarray', 'circkit', 'binteger'],

    ext_modules=[
        CTypesExtension(
            'wboxkit.libfastcircuit',
            sources=['src/wboxkit/fastcircuit.c'],
            depends=['src/wboxkit/fastcircuit.h'],
        )
    ],
    cmdclass={'build_ext': build_ext},

    entry_points = {
        'console_scripts': [
            'wboxkit.trace=wboxkit.attacks.trace:main',
            'wboxkit.exact=wboxkit.attacks.exact:main',
            'wboxkit.lda=wboxkit.attacks.lda:main',
        ],
    },

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Science/Research',
        'Topic :: Security :: Cryptography',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3',
    ],
)
