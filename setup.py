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

    package_data={
        # Include any files found in the 'scripts' subdirectory
        '': ['bin/*'],
    },

    version=VERSION,
    install_requires=['libtmux', 'pyyaml', 'psutil'],
    extras_require={
        'GRAPH': ['graphviz']
    },

    description='The Hyperion Launch Engine',
    author='David Leins',
    author_email='dleins@techfak.uni-bielefeld.de',
    url='https://github.com/DavidPL1/Hyperion.git',
    keywords=['libtmux'],
    classifiers=[],
    include_package_data=True,
    zip_safe=False
)
