from setuptools import setup, find_packages

import alnitak

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name='alnitak',
    version=alnitak.__version__,
    packages=find_packages(),

    install_requires=[
        'requests',
        'cryptography'
    ],


    entry_points={ 'console_scripts': [ 'alnitak = alnitak.main:main' ], },

    author='Karta Kooner',
    author_email='ksa.kooner@gmail.com',
    url='git remote add origin https://github.com/definitelyprobably/alnitak.git',
    description='Create and manage DANE (DNS TLSA) records',
    long_description=long_description,
    keywords="dane tlsa",
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
