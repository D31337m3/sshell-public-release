#!/usr/bin/env python3
"""
setup.py for sshell — installs pre-built C binaries.
The actual implementation is in C (see c-src/).  Build with `make` first,
then `pip install .` will place the compiled binaries on PATH via data_files.
"""
from setuptools import setup
import os

# Collect built binaries if present
_bin_dir = os.path.join(os.path.dirname(__file__), '.build')
_binaries = []
for name in ('sshell', 'sshell-daemon', 'sshell-player'):
    path = os.path.join(_bin_dir, name)
    if os.path.isfile(path):
        _binaries.append(path)

setup(
    name='sshell',
    version='1.6.3',
    description='Next-generation terminal multiplexer with network roaming, recording, and multi-user support',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='SShell Contributors',
    author_email='sshell@d31337m3.com',
    url='https://github.com/d31337m3/sshell',
    packages=[],
    data_files=[('bin', _binaries)] if _binaries else [],
    python_requires='>=3.7',
    install_requires=[],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: System :: Shells',
        'Topic :: Terminals',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    keywords='terminal multiplexer session tmux screen mosh',
    project_urls={
        'Bug Reports': 'https://github.com/d31337m3/sshell/issues',
        'Source': 'https://github.com/d31337m3/sshell',
        'Documentation': 'https://d31337m3.com/sshell',
    },
)
