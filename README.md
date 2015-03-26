# Parsers
Module with parsers that run various tools and return the result in json.

## Suported tools

* nmap
* wpscan
* joomscan
* sqlmap
* whatweb

## Instalation

pip install git+https://github.com/eonlight/parsers

or

git clone https://github.com/eonlight/parsers
cd parsers
./setup install

## Configuration

* The Module requires the applications to be installed and in the $PATH
    * It will run the `which' command looking for the supported tools in the $PATH

* It is also possible to modify the local settings file `~/.config/audits/parsers_settings.py' and specify the path to each binary

* Repositories for the requirements:
    * WPScan  - https://github.com/wpscanteam/wpscan
    * SQLMap  - https://github.com/sqlmapproject/sqlmap
    * WhatWeb - https://github.com/urbanadventurer/WhatWeb

* The config file also has the option to change the arguments passed to each tool