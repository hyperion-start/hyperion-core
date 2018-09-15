#!/usr/bin/env python
from setuptools import setup, find_packages

VERSION = '0.1'

setup(
    name='hyperion',
    packages=find_packages(),
    entry_points={
    'console_scripts': [
        'hyperion=hyperion:main',
		    ],
		},
    version=VERSION,
    install_requires=['webnsock', 'libtmux', 'pyyaml', 'psutil'],
    description='The Hyperion Launch Engine',
    author='David Leins',
    author_email='dleins@techfak.uni-bielefeld.de',
    url='https://github.com/DavidPL1/Hyperion.git',
    keywords=['webnsock', 'libtmux'],
    classifiers=[],
    include_package_data=True,
    zip_safe=False
)
