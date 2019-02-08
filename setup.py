from setuptools import setup, find_packages

import alnitak

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name='alnitak',
    version=alnitak.__version__,
    packages=find_packages(),

    setup_requires=[
        'pytest-runner',
        'requests>=2.21.0',
        'cryptography>=2.4.2',
    ],

    install_requires=[
        'requests>=2.21.0',
        'cryptography>=2.4.2',
    ],

    tests_require=[ 'pytest' ],


    entry_points={ 'console_scripts': [ 'alnitak = alnitak.main:main' ], },

    author='K. S. Kooner',
    author_email='ksa.kooner@gmail.com',
    license='MIT',
    url='https://github.com/definitelyprobably/alnitak',
    description='Create and manage DANE (DNS TLSA) records',
    long_description=long_description,
    keywords="dane tlsa",
    platforms="Linux, POSIX",
    classifiers=[
            "Development Status :: 4 - Beta",
            "Environment :: Console",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3.6",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX :: Linux",
            "Intended Audience :: System Administrators",
            "Topic :: Internet",
            "Topic :: Security",
            "Topic :: System :: Systems Administration",
            "Topic :: Utilities",
        ],

    )
