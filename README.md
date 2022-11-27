![last commit](https://img.shields.io/github/last-commit/groland11/nagios-check-speedtest.svg)
![languages](https://img.shields.io/github/languages/top/groland11/nagios-check-speedtest.svg)
![license](https://img.shields.io/github/license/groland11/nagios-check-speedtest.svg)

# nagios-check-security-updates
Nagios check for security updates in Red Hat Enterprise Linux

## Prerequisites
- Python 3.8

## Usage
```
./check-security-updates.py -h
usage: check-security-updates.py [-h] [-v] [-d]

Nagios check for security updates

optional arguments:
-h, --help            show this help message and exit
-v, --verbose         enable verbose output
-d, --debug           generate additional debugging output
```
## Examples
```
$ check-security-updates.py -v
```
