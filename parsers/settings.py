from subprocess import Popen, PIPE
from datetime import datetime
from sys import stderr, path, exit
import inspect
import os

version = '0.1.1'

which_bin = '/usr/bin/which'

nmap_bin = Popen([which_bin, 'nmap'], stdout=PIPE).communicate()[0].replace('\n', '')
sqlmap_bin =  Popen([which_bin, 'sqlmap'], stdout=PIPE).communicate()[0].replace('\n', '')
wpscan_bin =  Popen([which_bin, 'wpscan'], stdout=PIPE).communicate()[0].replace('\n', '')
whatweb_bin =  Popen([which_bin, 'whatweb'], stdout=PIPE).communicate()[0].replace('\n', '')
joomscan_bin = Popen([which_bin, 'joomscan'], stdout=PIPE).communicate()[0].replace('\n', '')

tools_folder = '%s/.config/audits' % os.getenv("HOME")
output_folder = '%s/output' % tools_folder

user_agent = 'ParsersWrapper/%s' % version

NMAP_OPTIONS = ['-sV', '-T4', '-p', '1-65535']
NMAP_OPTIONS_FAST = ['-sV', '-T4'];

WHATWEB_OPTIONS = ['-t', '4', '--user-agent', user_agent, '--no-errors', '--color', 'never', '-a', '4']
WHATWEB_FAST_OPTIONS = ['-t', '4', '--user-agent', user_agent, '--no-errors', '--color', 'never', '-a', '2']

WPSCAN_OPTIONS = ['--follow-redirection', '--threads', '2', '--force', '-a', user_agent, '--no-color', '--batch', '--enumerate', 'upt']
WPSCAN_PASSWORDS_FILE = '%s/passwords.txt' % tools_folder

SQLMAP_OPTIONS = ['--batch', '--flush-session', '--technique=EUSTQ', '--disable-coloring', '--user-agent=%s' % user_agent]

DEBUG = False
NMAP_FAST = False
WW_FAST = False

tools_name = 'parsers'

""" import local settings """
path.append(tools_folder)
try:
    import parsers_settings

    if hasattr(parsers_settings, 'DEBUG'): DEBUG = parsers_settings.DEBUG or DEBUG
    if hasattr(parsers_settings, 'NMAP_FAST'): NMAP_FAST = parsers_settings.NMAP_FAST or NMAP_FAST
    if hasattr(parsers_settings, 'WW_FAST'): WW_FAST = parsers_settings.WW_FAST or WW_FAST

    if hasattr(parsers_settings, 'tools_name'): tools_name = parsers_settings.tools_name or tools_name
    if hasattr(parsers_settings, 'output_folder'): output_folder = parsers_settings.output_folder or output_folder

    if hasattr(parsers_settings, 'which_bin'): which_bin = parsers_settings.which_bin

    # check if local settings has a different bin path
    if hasattr(parsers_settings, 'joomscan_bin'): joomscan_bin = parsers_settings.joomscan_bin
    if hasattr(parsers_settings, 'wpscan_bin'): wpscan_bin = parsers_settings.wpscan_bin
    if hasattr(parsers_settings, 'sqlmap_bin'): sqlmap_bin = parsers_settings.sqlmap_bin
    if hasattr(parsers_settings, 'whatweb_bin'): whatweb_bin = parsers_settings.whatweb_bin
    if hasattr(parsers_settings, 'nmap_bin'): nmap_bin = parsers_settings.nmap_bin

    # other options
    if hasattr(parsers_settings, 'user_agent'): user_agent = parsers_settings.user_agent

    if hasattr(parsers_settings, 'NMAP_OPTIONS'):  NMAP_OPTIONS = parsers_settings.NMAP_OPTIONS or NMAP_OPTIONS
    if hasattr(parsers_settings, 'NMAP_OPTIONS_FAST'):  NMAP_OPTIONS_FAST = parsers_settings.NMAP_OPTIONS_FAST or NMAP_OPTIONS_FAST

    if hasattr(parsers_settings, 'WHATWEB_OPTIONS'):  WHATWEB_OPTIONS = parsers_settings.WHATWEB_OPTIONS or WHATWEB_OPTIONS
    if hasattr(parsers_settings, 'WHATWEB_FAST_OPTIONS'):  WHATWEB_FAST_OPTIONS = parsers_settings.WHATWEB_FAST_OPTIONS or WHATWEB_FAST_OPTIONS

    if hasattr(parsers_settings, 'WPSCAN_OPTIONS'):  WPSCAN_OPTIONS = parsers_settings.WPSCAN_OPTIONS or WPSCAN_OPTIONS
    if hasattr(parsers_settings, 'WPSCAN_PASSWORDS_FILE'):  WPSCAN_PASSWORDS_FILE = parsers_settings.WPSCAN_PASSWORDS_FILE or WPSCAN_PASSWORDS_FILE

    if hasattr(parsers_settings, 'SQLMAP_OPTIONS'):  SQLMAP_OPTIONS = parsers_settings.SQLMAP_OPTIONS or SQLMAP_OPTIONS
except ImportError:
    stderr.write('%s - settings - parsers local settings not found.\n' % str(datetime.now()))


if not '/' in joomscan_bin:
    stderr.write('\033[91mWarning: No full path to the \033[0m\033[1mjoomscan\033[0m \033[91mbinary\033[0m\n')
if not '/' in wpscan_bin:
    stderr.write('\033[91mWarning: No full path to the \033[0m\033[1mwpscan\033[0m \033[91mbinary\033[0m\n')
if not '/' in sqlmap_bin:
    stderr.write('\033[91mWarning: No full path to the \033[0m\033[1msqlmap\033[0m \033[91mbinary\033[0m\n')
if not '/' in whatweb_bin:
    stderr.write('\033[91mWarning: No full path to the \033[0m\033[1mwhatweb\033[0m \033[91mbinary\033[0m\n')
if not '/' in nmap_bin:
    stderr.write('\033[91mWarning: No full path to the \033[0m\033[1mnmap\033[0m \033[91mbinary\033[0m\n')

try:
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print '\033[92mCreated %s\033[0m' % output_folder
    with open('%s/testfile.tmp' % output_folder, 'w'): pass
    with open('%s/testfile.tmp' % tools_folder, 'w'): pass
except OSError:
    print '\033[1mOne of the following errors occured:\033[0m'
    print '\033[91mNo permission to create %s\033[0m' % output_folder
    print '\033[91mNo permission to create a file in %s\033[0m' % output_folder
    print '\033[91mNo permission to create a file in %s\033[0m' % tools_folder
    exit(0)