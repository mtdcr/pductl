#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as fh:
        long_description = fh.read()

setup(
  name='atenpdu',
  version='0.3.2',
  author='Andreas Oberritter',
  author_email='obi@saftware.de',
  url='https://github.com/mtdcr/pductl',
  description='Interface for ATEN-PE PDUs',
  long_description=long_description,
  long_description_content_type="text/markdown",
  download_url='https://github.com/mtdcr/pductl',
  license='MIT',
  py_modules=['atenpdu'],
  scripts=['pductl'],
  classifiers=[
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: Home Automation',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: System :: Systems Administration',
    'Topic :: Utilities',
  ],
  install_requires=[
    'pysnmp>=4.3.2',
  ],
)
