#!/usr/bin/env python

from distutils.core import setup

setup(
  name='atenpdu',
  version='0.1',
  author='Andreas Oberritter',
  author_email='obi@saftware.de',
  url='https://github.com/mtdcr/pductl',
  description='Interface for ATEN-PE PDUs',
  download_url='https://github.com/mtdcr/pductl',
  license='MIT',
  py_modules=['atenpdu'],
  scripts=['pductl'],
)
