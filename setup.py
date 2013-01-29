import glob
import os
import re

from distutils.core import setup


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('__init__.py').read()).group('version')

setup(name='ts_analyser', 
      version          = get_version(), 
      author           = 'Tijmen de Mes',
      author_email     = 'tijmen@vck.utwente.nl',
      description      = "A TS analyser",
      license          = "GPL",
      platforms        = ["Platform Independent"],
      classifiers      = [
          "Development Status :: 3 - Alpha",
          "Intended Audience :: Cable Operators",
          "License :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
      ],)