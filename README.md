![last commit](https://img.shields.io/github/last-commit/groland11/nagios-check-security-updates.svg)
![languages](https://img.shields.io/github/languages/top/groland11/nagios-check-security-updates.svg)
![license](https://img.shields.io/github/license/groland11/nagios-check-security-updates.svg)

# nagios-check-security-updates
Nagios check for security updates in Red Hat Enterprise Linux
- Performance data for available patches in each severity level
- Timeframe in which security patches must be applied and no warning is issued
  Criticcal: 30 days
  Important, Moderate, Low: 90 days
- Patch information is cached in local file to minimize online requests. Patch information older than 1 year is automatically removed from cache file.

## Prerequisites
- Python >= 3.6
- Red Hat Enterprise Linux >= 7

## Usage
```
./check-security-updates.py -h
usage: check-security-updates.py [-h] [-v] [-d] [-k] [-c] [-V]

Nagios check for security updates

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  enable verbose output
  -d, --debug    enable debug output
  -k, --kernel   ommit kernel patches (if kernel live patches are enabled)
  -c, --cache    local cache file for patch dates (default: /tmp/check-security-updates.cache)
  -V, --version  show program's version number and exit
```
## Examples
```
$ check-security-updates.py -v
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-5.14.0-162.6.1.el9_1.x86_64
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-core-5.14.0-162.6.1.el9_1.x86_64
2022-11-27 19:18:52 [110868] INFO: Moderate: kernel-modules-5.14.0-162.6.1.el9_1.x86_64
WARNING: Critical=0 Important=0 Moderate=3 Low=0 next_patch_date=None|Critical=0;Important=0;Moderate=3;Low=0;

$ check-security-updates.py
WARNING: Critical=0 Important=0 Moderate=3 Low=0 next_patch_date=2023-02-22|Critical=0;Important=0;Moderate=3;Low=0;
```
