#!/usr/bin/env python3
""" Nagios check for security updates

Requirements
    Python >= 3.8

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""
import argparse
import logging
import re
import sys
from subprocess import run, TimeoutExpired, PIPE

__license__ = "GPLv3"
__version__ = "0.1"

# Nagios return codes: https://nagios-plugins.org/doc/guidelines.html#AEN78
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3
return_codes = ['OK', 'WARNING', 'CRITICAL', 'UNKNOWN']
DEBUG = False

# Global logging object
logger = logging.getLogger(__name__)


def parseargs() -> argparse.Namespace:
    """ Parse command-line arguments """
    parser = argparse.ArgumentParser(description='Nagios check for security updates')
    parser.add_argument(
        '-v', '--verbose', required=False,
        help='enable verbose output', dest='verbose',
        action='store_true')
    parser.add_argument(
        '-d', '--debug', required=False,
        help='enable debug output', dest='debug',
        action='store_true')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    args = parser.parse_args()
    return args


class Updates:
    def __init__(self):
        self.rc = -1
        self.critical = []
        self.important = []
        self.moderate = []
        self.low = []

    def run(self, cmd: list, verbose: bool=False):
        """List security updates and return result"""
        output = ""

        try:
            logger.debug(f'Running OS command line: {cmd} ...')
            process = run(cmd, check=True, timeout=60, stdout=PIPE)
            self.rc = process.returncode
            output = process.stdout.decode('utf-8').splitlines()
        except (TimeoutExpired, ValueError) as e:
            logger.warning(f'{e}')
            sys.exit(UNKNOWN)
        except FileNotFoundError as e:
            logger.critical(f"CRITICAL: Missing program {cmd[0] if len(cmd) > 0 else ''} ({e})")
            sys.exit(CRITICAL)
        except Exception as e:
            logger.critical(f'CRITICAL: {e}')
            sys.exit(CRITICAL)

        for line in output:
            m = re.search(r"Critical/Sec.\s*(.*)$", line)
            if m:
                logger.debug(line)
                self.critical.append(m.group(0))
                if verbose:
                    logger.info(f"Critical: {m.group(1)}")
            m = re.search(r"Important/Sec.\s*(.*)$", line)
            if m:
                logger.debug(line)
                self.important.append(m.group(0))
                if verbose:
                    logger.info(f"Important: {m.group(1)}")
            m = re.search(r"Moderate/Sec.\s*(.*)$", line)
            if m:
                logger.debug(line)
                self.moderate.append(m.group(0))
                if verbose:
                    logger.info(f"Moderate: {m.group(1)}")
            m = re.search(r"Low/Sec.\s*(.*)$", line)
            if m:
                logger.debug(line)
                self.low.append(m.group(0))
                if verbose:
                    logger.info(f"Low: {m.group(1)}")

    def create_output(self) -> tuple:
        """Verify result and return output in Nagios format"""
        if self.rc >= 0:
            result = OK
        else:
            return UNKNOWN, f'{return_codes[UNKNOWN]}'

        if len(self.critical) > 0:
            result = CRITICAL
        if len(self.important) > 0 or len(self.moderate) > 0 or len(self.low) > 0:
            result = WARNING

        msg = f'{return_codes[result]}: Critical={len(self.critical)} Important={len(self.important)} ' \
              f'Moderate={len(self.moderate)} Low={len(self.low)}'
        perfdata = f'Critical={len(self.critical)};' \
                   f'Important={len(self.important)};' \
                   f'Moderate={len(self.moderate)};' \
                   f'Low={len(self.low)};'

        message = f'{msg}|{perfdata}'
        logger.debug(message)
        return result, message


class LogFilterWarning(logging.Filter):
    """Logging filter >= WARNING"""
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.INFO, logging.WARNING)


def get_logger(debug: bool = False) -> logging.Logger:
    """Retrieve logging object"""
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Log everything >= WARNING to stdout
    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(logging.DEBUG)
    h1.setFormatter(logging.Formatter(fmt='%(asctime)s [%(process)d] %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    h1.addFilter(LogFilterWarning())

    # Log errors to stderr
    h2 = logging.StreamHandler(sys.stderr)
    h2.setFormatter(logging.Formatter(fmt='%(asctime)s [%(process)d] %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    h2.setLevel(logging.ERROR)

    logger.addHandler(h1)
    logger.addHandler(h2)

    return logger


def main():
    """Main program flow"""
    result = OK

    args = parseargs()
    get_logger(args.debug)

    # Retrieve list of updates
    updates = Updates()
    updates.run(['yum', 'updateinfo', 'list'], args.verbose)
    result, message = updates.create_output()
    print(message)

    exit(result)


if __name__ == '__main__':
    main()
