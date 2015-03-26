# this are the default options

tools_name = 'parsers'
tools_folder = '{{ home }}/.config/audits'
output_folder = '{{ home }}/.config/audits/output'
user_agent = 'SapoParsers/{{ version }}'

NMAP_OPTIONS = ['-Pn', '-sC', '-p', '1-65535']
NMAP_OPTIONS_FAST = ['-Pn'];

WHATWEB_OPTIONS = ['-t', '10', '--user-agent', user_agent, '--no-errors', '--color', 'never', '-a', '4']
WHATWEB_FAST_OPTIONS = ['-t', '10', '--user-agent', user_agent, '--no-errors', '--color', 'never', '-a', '2']

WPSCAN_OPTIONS = ['--follow-redirection', '--threads', '2', '--force', '-a', user_agent, '--no-color', '--batch', '--enumerate', 'upt']
WPSCAN_PASSWORDS_FILE = '%s/passwords.txt' % tools_folder

SQLMAP_OPTIONS = ['--batch', '--flush-session', '--technique=EUSTQ', '--disable-coloring', '--user-agent=%s' % user_agent]

# binaries - you can define which binaries to use:

which_bin = '/usr/bin/which'

# joomscan_bin = '/usr/bin/joomscan'
# wpscan_bin = '/usr/bin/wpscan'
# sqlmap_bin = '/usr/bin/sqlmap'
# whatweb_bin = '/usr/bin/whatweb'
# nmap_bin = '/usr/bin/nmap'

# other options

DEBUG = False
NMAP_FAST = False
WW_FAST = True
