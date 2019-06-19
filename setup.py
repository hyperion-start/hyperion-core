#!/usr/bin/env python
from setuptools import find_packages
from distutils.core import setup
from catkin_pkg.python_setup import generate_distutils_setup

VERSION = '2.2.0'

setup_args = generate_distutils_setup(
    name='hyperion',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hyperion=hyperion:main',
        ],
    },

    package_data={
        # Include any files found in the 'scripts' subdirectory
        '': ['bin/*', 'data/*'],
    },

    version=VERSION,
    install_requires=['libtmux',
                      'pyyaml',
                      'psutil',
                      'enum34',
                      'selectors2;python_version<"3.4"'],

    description='The Hyperion Launch Engine',
    author='David Leins',
    author_email='dleins@techfak.uni-bielefeld.de',
    url='https://github.com/DavidPL1/Hyperion.git',
    keywords=['libtmux'],
    classifiers=[],
    include_package_data=True
)

setup(**setup_args)
