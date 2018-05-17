import sys

try:
    import setuptools
    from setuptools import setup
except ImportError:
    setuptools = None
    from distutils.core import setup

version = '0.0.1'

kwargs = {}

if setuptools is not None:

    if sys.version_info < (3, 4):
        kwargs['install_requires']= ['enum34']

setup(
    name='tornado_m2crypto',
    version=version,
    packages=['tornado_m2crypto', 'tornado_m2crypto.test'],
    **kwargs)
