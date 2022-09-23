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
    version='0.2.0',
    description='White-box Design & Cryptanalyis Kit',
    author='Aleksei Udovenko',
    author_email='aleksei@affine.group',
    url='https://github.com/hellman/wboxkit',

    packages=find_packages("src"),
    package_dir={'': 'src'},

    ext_modules=[
        CTypesExtension(
            'wboxkit.fastcircuit',
            ['src/wboxkit/fastcircuit.c'],
        )
    ],
    cmdclass={'build_ext': build_ext},

    entry_points = {
        'console_scripts': [
            'wboxkit.trace=wboxkit.attacks.trace:main'
            'wboxkit.exact=wboxkit.attacks.exact:main'
        ],
    }
)
