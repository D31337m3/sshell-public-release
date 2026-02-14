#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='sshell',
    version='1.6.1',
    description='Next-generation terminal multiplexer with network roaming, recording, and multi-user support',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='SShell Contributors',
    author_email='sshell@d31337m3.com',
    url='https://github.com/d31337m3/sshell',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sshell=sshell.client.cli:main',
            'sshell-daemon=sshell.daemon.manager:main',
        ],
    },
    python_requires='>=3.7',
    install_requires=[],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
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
