![last commit](https://img.shields.io/github/last-commit/groland11/nagios-check-speedtest.svg)
![languages](https://img.shields.io/github/languages/top/groland11/nagios-check-speedtest.svg)
![license](https://img.shields.io/github/license/groland11/nagios-check-speedtest.svg)

# nagios-check-security-updates
Nagios check for security updates in Red Hat Enterprise Linux
- Performance data for each severity level
- Timeframe in which security patches may be applied and no warning is issued

## Prerequisites
- Python >= 3.8
- Red Hat Enterprise Linux >= 8

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
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-5.14.0-162.6.1.el9_1.x86_64
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-core-5.14.0-162.6.1.el9_1.x86_64
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-modules-5.14.0-162.6.1.el9_1.x86_64
WARNING: Critical=0 Important=0 Moderate=3 Low=0|Critical=0;Important=0;Moderate=3;Low=0;

$ check-security-updates.py
WARNING: Critical=0 Important=0 Moderate=3 Low=0|Critical=0;Important=0;Moderate=3;Low=0;
```
