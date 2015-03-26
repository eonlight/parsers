from subprocess import Popen, PIPE
import json
import os
import re

# for error handdling
from datetime import datetime
from sys import stderr
import traceback

import settings

class JoomlaParser():

    def __init__(self, tool=None):
        if settings.DEBUG:
            print '%s - JoomlaParser - __init__ - Creating JoomlaParser object...' % str(datetime.now())

        self.executable = settings.joomscan_bin.split(' ') if ' ' in settings.joomscan_bin else [settings.joomscan_bin]
        self.result = None
        settings.tools_name = tool or settings.tools_name

    def execute(self, url=None):
        if settings.DEBUG:
            print '%s - JoomlaParser - execute - Starting to execute joomla scan...' % str(datetime.now())

        if not url or not self.executable:
            if settings.DEBUG:
                print '%s - JoomlaParser - execute - No url or no executable...' % str(datetime.now())
            return None

        params = self.executable + ['-u', url]

        try:
            with open(os.devnull, "w") as fnull:
                self.result = Popen(params, stdout=PIPE, stderr=fnull).communicate()[0]
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - JoomlaParser - execute - Error while executing joomla scan: %s\n" % (str(datetime.now()), e.message))

        # log result to an output_folder - tries to create the folder if it does not exist
        if os.path.exists(settings.output_folder) and os.path.isdir(settings.output_folder):
            directory = '%s/%s' % (settings.output_folder, url.replace('http://', '').replace('https://', '').split('/')[0])
            if os.path.exists(directory) and os.path.isdir(directory) and os.access(directory, os.W_OK):
                filename = '%s/%s.joomlascan.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            elif os.access(settings.output_folder, os.W_OK):
                os.mkdir(directory)
                filename = '%s/%s.joomlascan.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            else:
                stderr.write('%s - JoomlaParser - execute - Cannot write joomla scan result in file\n' % str(datetime.now()))
        else:
            stderr.write('%s - JoomlaParser - execute - %s directory does not exist\n' % (str(datetime.now()), settings.output_folder))

        return self.parse()

    def parse(self, result=None):
        if settings.DEBUG:
            print '%s - JoomlaParser - parse - Starting to parse joomla scan result...' % str(datetime.now())

        result = result or self.result

        if not result:
            if settings.DEBUG:
                print '%s - JoomlaParser - parse - No result to be parsed...' % str(datetime.now())
            return {'version': None, 'plugins_number': 0, 'active_plugins': [], 'vulnerable_number': 0, 'vulnerable_plugins': []}

        version = None
        nplugins = vplugins = 0

        try:
            version = JoomlaParser.parse_version(result)
            nplugins, vplugins = JoomlaParser.parse_nplugins(result)
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - JoomlaParser - parse - Error parsing version and plugin number: %s\n" % (str(datetime.now()), e.message))

        plugins = aplugins = []
        for plugin in re.finditer('# \d+\n(.*\n){5}', result, re.MULTILINE):
            try:
                plugin = JoomlaParser.parse_plugin(plugin.group())
            except (ValueError, Exception) as e:
                if settings.DEBUG:
                    stderr.write(traceback.format_exc())
                stderr.write("%s - JoomlaParser - parse - Error parsing the plugin: %s\n" % (str(datetime.now()), e.message))
                continue

            plugins.append(plugin) if plugin['vulnerable'] else aplugins.append(plugin)

        return {'version': version, 'plugins_number': nplugins, 'active_plugins': aplugins, 'vulnerable_number': vplugins, 'vulnerable_plugins': plugins}

    @staticmethod
    def parse_version(result):
        if 'version range is :' in result:
            return re.search('version range is : \[(\d+.)+ - (\d+.)+\]', result).group().replace('version range is : ', '')
        elif 'version found is' in result:
            return re.search('version found is (\d+.)+', result).group().replace('version found is ', '')
        return None

    @staticmethod
    def parse_plugin(plugin):
        vulnerable = True
        if 'Vulnerable? Yes' not in plugin:
            vulnerable = False

        vulnerability = re.search('Info -> .*', plugin).group().replace('Info -> ', '').strip()

        version = re.search('Versions? (A|e)ffected: .*', plugin)
        if version:
            version = version.group().replace('Versions Affected: ', '').replace('<=', '').strip()

        if vulnerable and 'Exploit' in plugin:
            return {'vulnerable': vulnerable, 'vulnerability': vulnerability, 'version': version, 'exploit': plugin.split('Exploit: ')[1].split('Vulnerable?')[0]}

        return {'vulnerable': vulnerable, 'vulnerability': vulnerability, 'version': version}

    @staticmethod
    def parse_nplugins(result):
        nplugins = re.search('in \d+ found entries', result).group().replace('in ', '').replace(' found entries', '')
        vplugins = re.search('There are \d+ vulnerable points', result).group().replace('There are ', '').replace(' vulnerable points', '')
        return nplugins, vplugins


class WordPressParser():

    def __init__(self, tool=None):
        if settings.DEBUG:
            print '%s - WordPressParser - __init__ - Creating WordPressParser object...' % str(datetime.now())

        self.executable = settings.wpscan_bin.split(' ') if ' ' in settings.wpscan_bin else [settings.wpscan_bin]
        self.result = None
        settings.tools_name = tool or settings.tools_name

    def execute(self, url=None, bauth=None, bruteforce=False):
        if settings.DEBUG:
            print '%s - WordPressParser - execute - Starting to execute wpscan...' % str(datetime.now())

        if not url or not self.executable:
            if settings.DEBUG:
                print '%s - WordPressParser - execute - No url or no executable...' % str(datetime.now())
            return None

        # check if there are additional options
        params = self.executable + settings.WPSCAN_OPTIONS + ['--url', url]
        if bruteforce and settings.WPSCAN_PASSWORDS_FILE:
            params += ['--wordlist', settings.WPSCAN_PASSWORDS_FILE]
        if bauth:
            params += ['--basic-auth', '%s:%s' % (bauth['user'], bauth['pass'])]

        try:
            with open(os.devnull, "w") as fnull:
                self.result = Popen(params, stdout=PIPE, stderr=PIPE).communicate()[0]
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - WordPressParser - execute - Error while executing wpscan: %s\n" % (str(datetime.now()), e.message))

        # log result to an output_folder - tries to create the folder if it does not exist
        if os.path.exists(settings.output_folder) and os.path.isdir(settings.output_folder):
            directory = '%s/%s' % (settings.output_folder, url.replace('http://', '').replace('https://', '').split('/')[0])
            if os.path.exists(directory) and os.path.isdir(directory) and os.access(directory, os.W_OK):
                filename = '%s/%s.wpscan.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            elif os.access(settings.output_folder, os.W_OK):
                os.mkdir(directory)
                filename = '%s/%s.wpscan.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            else:
                stderr.write('%s - WordPressParser - execute - Cannot write WPScan result in file\n' % str(datetime.now()))
        else:
            stderr.write('%s - WordPressParser - execute - %s does not exist\n' % (str(datetime.now()), settings.output_folder))

        return self.parse()

    def parse(self, result=None):
        if settings.DEBUG:
            print '%s - WordPressParser - parse - Starting to parse wpscan result...' % str(datetime.now())

        result = result or self.result

        if not result:
            if settings.DEBUG:
                print '%s - WordPressParser - parse - No result to be parsed...' % str(datetime.now())
            return {'version': None, 'nplugins': 0, 'plugins': {}, 'users': {}}

        try:
            version = re.search('WordPress version (\d+.?)+', result).group().replace('WordPress version ', '').strip()
            nplugins = int(re.search('\d+ plugins found', result).group().replace(' plugins found', ''))
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - WordPressParser - parse - Error while parsing wpscan version and plugin number: %s\n" % (str(datetime.now()), e.message))
            version = None
            nplugins = 100

        plugins = users = []
        pcount = -1
        plugin = {}
        save = save_users = False
        for line in result.split('\n'):
            if 'plugins found' in line:
                pcount = 0

            if pcount > -1 and pcount < nplugins and 'Name' in line:
                if save:
                    plugins.append(plugin)

                save = False
                try:
                    plugin = WordPressParser.parse_plugin(line)

                    if not plugin['vulnerable']:
                        plugins.append(plugin)
                    else:
                        plugin['message'] = ''
                        save = True
                    pcount += 1
                except (ValueError, Exception) as e:
                    if settings.DEBUG:
                        stderr.write(traceback.format_exc())
                    stderr.write("%s - WordPressParser - parse - Error while parsing wpscan plugin: %s\n" % (str(datetime.now()), e.message))

            if save:
                plugin['message'] = '%s\n%s' % (plugin['message'], line)

            if save_users:
                users = '%s\n%s' % (users, line)
                if line == '':
                    save_users = False

            if 'Password' in line and 'Login' in line and 'Name' in  line:
                users = line
                save_users = True

        return {'version': version, 'nplugins': nplugins, 'plugins': plugins, 'users': users}

    @staticmethod
    def parse_plugin(line):
        version = re.search('(\d.?)+', line)
        if version:
            version = version.group()

        name = re.search('Name: .+(( -)|)', line)
        if name:
            name = name.group().replace('Name: ', '').replace(' -', '')

        vulnerable = True
        if '[+]' in line:
            vulnerable = False

        return {'name': name, 'version': version, 'vulnerable': vulnerable}


class SQLMapParser():

    def __init__(self, tool=None):
        if settings.DEBUG:
            print '%s - SQLMapParser - __init__ - Creating SQLMapParser object...' % str(datetime.now())

        self.executable = settings.sqlmap_bin.split(' ') if ' ' in settings.sqlmap_bin else [settings.sqlmap_bin]
        self.result = None
        settings.tools_name = tool or settings.tools_name

    def execute(self, url=None, param=None, filename=None, auth=None):
        if settings.DEBUG:
            print '%s - SQLMapParser - execute - Starting to execute sqlmap_bin...' % str(datetime.now())

        if not url or not self.executable:
            if settings.DEBUG:
                print '%s - SQLMapParser - execute - No url or no executable...' % str(datetime.now())
            return None

        params = self.executable + settings.SQLMAP_OPTIONS + ['-u', url]
        if auth:
            if isinstance(auth, dict):
                auth = '%s:%s' % (auth['username'], auth['password'])
            params += ['--auth-type', 'Basic', '--auth-cred', auth]

        if filename:
            params += ['-r', filename]

        if param:
            params += ['-p', param]

        try:
            with open(os.devnull, "w") as fnull:
                self.result = Popen(params, stdout=PIPE, stderr=fnull).communicate()[0]
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - SQLMapParser - execute - Error while executing sqlmap: %s\n" % (str(datetime.now()), e.message))

        # log result to an output_folder - tries to create the folder if it does not exist
        if os.path.exists(settings.output_folder) and os.path.isdir(settings.output_folder):
            directory = '%s/%s' % (settings.output_folder, url.replace('http://', '').replace('https://', '').split('/')[0])
            if os.path.exists(directory) and os.path.isdir(directory) and os.access(directory, os.W_OK):
                filename = '%s/%s.sqlmap.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            elif os.access(settings.output_folder, os.W_OK):
                os.mkdir(directory)
                filename = '%s/%s.sqlmap.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            else:
                stderr.write('%s - SQLMapParser - execute - Cannot write WPScan result in file\n' % str(datetime.now()))
        else:
            stderr.write('%s - SQLMapParser - execute - %s does not exist\n' % (str(datetime.now()), settings.output_folder))

        return self.parse()

    def parse(self, result=None):
        if settings.DEBUG:
            print '%s - SQLMapParser - parse - Starting to parse sqlmap result...' % str(datetime.now())

        result = result or self.result

        if not result:
            if settings.DEBUG:
                print '%s - SQLMapParser - parse - No result to be parsed...' % str(datetime.now())
            return {'vulnerable': False, 'parameters_number': 0, 'parameters': []}

        vulnerable = False
        nparams = 0
        params = []

        for param in re.finditer('Place: .*\nParameter: .*\n(.*\n){3}', result, re.MULTILINE):
            try:
                param = SQLMapParser.parse_param(param.group())
            except (ValueError, Exception) as e:
                if settings.DEBUG:
                    stderr.write(traceback.format_exc())
                stderr.write("%s - SQLMapParser - parse - Error while parsing parameter sqlmap: %s\n" % (str(datetime.now()), e.message))
            params.append(param)
            nparams += 1
            vulnerable = True

        return {'vulnerable': vulnerable, 'parameters_number': nparams, 'parameters': params}

    @staticmethod
    def parse_param(param):
        try:
            name = re.search('Parameter: .*', param).group().replace('Parameter: ', '')
            payload = re.search('Payload: .*', param).group().replace('Payload: ', '')
        except AttributeError:
            return {'name': 'error parsing', 'payload': 'error parsing'}

        return {'name': name, 'payload': payload}


class NMapParser():
    def __init__(self, tool=None):
        if settings.DEBUG:
            print '%s - NMapParser - __init__ - Creating NMapParser object...' % str(datetime.now())

        self.executable = settings.nmap_bin.split(' ') if ' ' in settings.nmap_bin else [settings.nmap_bin]
        self.result = None
        settings.tools_name = tool or settings.tools_name

    def execute(self, url=None):
        if settings.DEBUG:
            print '%s - NMapParser - execute - Starting to execute nmap...' % str(datetime.now())

        if not url or not self.executable:
            if settings.DEBUG:
                print '%s - NMapParser - execute - No url or no executable...' % str(datetime.now())
            return None

        url = url.replace('http://', '').replace('https://', '')

        params = self.executable + (settings.NMAP_OPTIONS_FAST if settings.NMAP_FAST else settings.NMAP_OPTIONS) + [url]
        try:
            with open(os.devnull, "w") as fnull:
                self.result = Popen(params, stdout=PIPE, stderr=fnull).communicate()[0]
        except(ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - NMapParser - parse - Error while executing nmap: %s\n" % (str(datetime.now()), e.message))

        if os.path.exists(settings.output_folder) and os.path.isdir(settings.output_folder):
            directory = '%s/%s' % (settings.output_folder, url.replace('http://', '').replace('https://', '').split('/')[0])
            if os.path.exists(directory) and os.path.isdir(directory) and os.access(directory, os.W_OK):
                filename = '%s/%s.nmap.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            elif os.access(settings.output_folder, os.W_OK):
                os.mkdir(directory)
                filename = '%s/%s.nmap.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            else:
                stderr.write('%s - NMapParser - execute - Cannot write nmap result in file\n' % str(datetime.now()))
        else:
            stderr.write('%s - NMapParser - execute - %s does not exist or no url provided\n' % (str(datetime.now()), settings.output_folder))

        return self.parse()

    def parse(self, result=None):
        if settings.DEBUG:
            print '%s - NMapParser - parse - Starting to parse nmap result...' % str(datetime.now())
        result = result or self.result
        return result


class WhatWebParser():
    def __init__(self, log=None, tool=None):
        if settings.DEBUG:
            print '%s - WhatWebParser - __init__ - Creating WhatWebParser object...' % str(datetime.now())

        self.executable = settings.whatweb_bin.split(' ') if ' ' in settings.whatweb_bin else [settings.whatweb_bin]
        self.log = log
        self.result = None
        settings.tools_name = tool or settings.tools_name

    def execute(self, url=None, bauth=None):
        if settings.DEBUG:
            print '%s - WhatWebParser - execute - Starting to execute whatweb...' % str(datetime.now())

        if not url or not self.executable:
            if settings.DEBUG:
                print '%s - WhatWebParser - execute - No url or no executable...' % str(datetime.now())
            return None

        #if 'http://' not in url and 'https://' not in url:
            #url = 'http://%s' % url

        url = url.replace('http://', '').replace('https://', '')

        log = self.log or '%s/%s.whatweb.json' % (settings.output_folder, settings.tools_name)

        # clean log
        with open(log, 'w'):
            pass

        params = self.executable + (settings.WHATWEB_FAST_OPTIONS if settings.WW_FAST else settings.WHATWEB_OPTIONS)
        if bauth:
            params += ['-u', '%s:%s' % (bauth['user'], bauth['pass'])]
        params += ['--log-json', log, url]

        try:
            with open(os.devnull, "w") as fnull:
                self.result, err = Popen(params, stdout=PIPE, stderr=PIPE).communicate()
        except (ValueError, Exception) as e:
            if settings.DEBUG:
                stderr.write(traceback.format_exc())
            stderr.write("%s - WhatWebParser - execute - Error while executing whatweb: %s\n" % (str(datetime.now()), e.message))

        if os.path.exists(settings.output_folder) and os.path.isdir(settings.output_folder):
            directory = '%s/%s' % (settings.output_folder, url.replace('http://', '').replace('https://', '').split('/')[0])
            if os.path.exists(directory) and os.path.isdir(directory) and os.access(directory, os.W_OK):
                filename = '%s/%s.whatweb.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            elif os.access(settings.output_folder, os.W_OK):
                os.mkdir(directory)
                filename = '%s/%s.whatweb.txt' % (directory, settings.tools_name)
                with open(filename, 'w') as f:
                    f.write('%s\n' % ' '.join(params))
                    f.write(self.result)
            else:
                stderr.write('%s - WhatWebParser - execute - Cannot write whatweb result in file\n' % str(datetime.now()))
        else:
            stderr.write('%s - WhatWebParser - execute - %s does not exist or no url provided\n' % (str(datetime.now()), settings.output_folder))

        return self.parse()

    def parse(self, result=None):
        if settings.DEBUG:
            print '%s - WhatWebParser - parse - Starting to parse whatweb...' % str(datetime.now())

        if result:
            return WhatWebParser.parse_output(result)

        log = self.log or '%s/%s.whatweb.json' % (settings.output_folder, settings.tools_name)
        # get last line
        for result in open(log, 'r'):
            pass


        if not settings.DEBUG:
            with open(log, 'w'):
                pass

        try:
            result = json.loads(result);
            if not result:
                raise Exception
        except (ValueError, Exception):
            stderr.write('%s - WhatWebParser - parse - Error loading json content\n' % str(datetime.now()))
            stderr.write('%s - WhatWebParser - parse - Starting to parse output\n' % str(datetime.now()))
            # parse output
            if not self.result:
                if settings.DEBUG:
                    print '%s - WhatWebParser - parse - No result to be parsed...' % str(datetime.now())
                return None

            return WhatWebParser.parse_output(self.result)

        plugins = {}
        for key, item in result['plugins'].iteritems():
            name = key.lower()
            plugins[name] = item

        return plugins

    @staticmethod
    def parse_output(output):
        if settings.DEBUG:
            print '%s - WhatWebParser - parse_output - Starting to parse whatweb output...' % str(datetime.now())
        url, code, output = output.split(' ', 2)
        results = {url: ['Response Code: %s' % code.replace('[', '').replace(']', '')]}
        for item in output.split(', '):
            key = item.split('[')[0].strip().lower()
            values = []
            if '[' in item:
                start = True
                for value in item.split('['):
                    if not start:
                        values.append(value.replace(']', '').strip().lower())
                    start = False
            results[key] = values
        return results
