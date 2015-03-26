#! /usr/bin/env python
from setuptools import setup, find_packages

from sys import exit, argv
import os

version = "0.0.3"
home = os.getenv("HOME")
file_path = os.path.realpath(__file__).rsplit('/', 1)[0]

class bcolors:
    FAIL = '\033[91m'
    ENF  = '\033[1m'
    OK  = '\033[92m'
    ENDC = '\033[0m'

tools_folder = '%s/.config/audits' % home
settings_filename = '%s/parsers_settings.py' % tools_folder

if 'install' in argv or 'develop' in argv:
    if not os.path.exists(tools_folder):
        try:
            os.mkdir(tools_folder)
        except OSError:
            print '%sNo permission to create %s.%s' % (bcolors.FAIL, tools_folder, bcolors.ENDC)
            exit(0)

        print '%s%s created.%s' % (bcolors.OK, tools_folder, bcolors.ENDC)

    #copy template to place
    if os.path.exists(settings_filename):
        try:
            os.rename(settings_filename, '%s/parsers_settings-old.py' % tools_folder)
        except OSError:
            print '%sCould not move old settings file.%s' % (bcolors.FAIL, bcolors.ENDC)
            exit(0)

    print '%s%s moved to %s/parsers_settings-old.py .%s' % (bcolors.OK, settings_filename, tools_folder, bcolors.ENDC)

    with open('%s/parsers/parsers_settings.template.py' % file_path) as f:
        lines = f.readlines()
        with open(settings_filename, 'w') as w:
            for line in lines:
                w.write(line.replace('{{ home }}', home).replace('{{ version }}', version))

    print '%s%s created.%s' % (bcolors.OK, settings_filename, bcolors.ENDC)

setup(
    name="parsers",
    version=version,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={},
    author='Ruben de Campos',
    author_email='rcadima@gmail.com',
    description='Audit Tools Parsers',
    keywords=['audit', 'tools', 'parsers', 'sqlmap', 'wpscan', 'joomscan', 'whatweb', 'nmap'],
    long_description=""" Module with parsers that run various tools and return the result in json. """
)
