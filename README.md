# Parsers
Module with parsers that run various tools and return the result in json.

## Suported tools

* nmap
* wpscan
* joomscan
* sqlmap
* whatweb

## Installation

`pip install git+https://github.com/eonlight/parsers`

or

```
git clone https://github.com/eonlight/parsers
cd parsers
./setup.py install
```

## Configuration

* The Module requires the applications to be installed and in the $PATH
    * It will run the `which' command looking for the supported tools in the $PATH

* It is also possible to modify the local settings file `~/.config/audits/parsers_settings.py' and specify the path to each binary

* Repositories for the requirements:
    * WPScan  - https://github.com/wpscanteam/wpscan
    * SQLMap  - https://github.com/sqlmapproject/sqlmap
    * WhatWeb - https://github.com/urbanadventurer/WhatWeb

* The config file also has the option to change the arguments passed to each tool

## To Do List

* Make Nmap Parser a little bit more intelligent to report more data other than versions

## ChangeLog

### version 0.1.0 (current)

* NMapParser is more intelligent
* Now returns a json result with product, name and version

### version 0.0.3

* Initial official verison
* Fixes bugs
