#!/usr/bin/env python

IS_CATKIN = False

try:
    from catkin_pkg.python_setup import generate_distutils_setup
    import selectors
    from setuptools import setup, find_packages
    IS_CATKIN = True
except ImportError:
    from setuptools import setup, find_packages
    pass


VERSION = '2.2.0'

setup_args = dict(
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
                      'enum34;python_version<"3.4"',
                      'selectors2;python_version<"3.4"'],

    description='The Hyperion Launch Engine',
    author='David Leins',
    author_email='dleins@techfak.uni-bielefeld.de',
    url='https://github.com/DavidPL1/Hyperion.git',
    keywords=['libtmux'],
    classifiers=[],
    include_package_data=True
)

if IS_CATKIN:
    setup_args = generate_distutils_setup(
        **setup_args
    )

setup(**setup_args)
