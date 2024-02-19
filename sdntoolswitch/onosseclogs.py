from __future__ import print_function
import argparse
import logging
import logging.handlers
import sys

APP_NAME = __package__.rsplit('.', 1)[-1]
sys.argv = ['']
del sys


def create_logger(app_name, log_level=logging.DEBUG, stdout=False, syslog=False, file=True):
    """
    create logging object with logging to syslog, file and stdout
    :param app_name app name
    :param log_level logging log level
    :param stdout log to stdout
    :param syslog log to syslog
    :param file log to file
    :return: logging object
    """
    # disable requests logging
    # logging.getLogger("requests").setLevel(logging.ERROR)
    # logging.getLogger("urllib3").setLevel(logging.ERROR)

    # create logger
    logger = logging.getLogger(app_name)
    logger.setLevel(log_level)

    # set log format to handlers
    formatter = logging.Formatter('%(name)s - %(asctime)s - %(levelname)s - %(message)s')

    if file and not logger.handlers:
        # create file logger handler
        fh = logging.FileHandler('onossec.log')
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if syslog:
        # create syslog logger handler
        sh = logging.handlers.SysLogHandler(address='/dev/log')
        sh.setLevel(log_level)
        sf = logging.Formatter('%(name)s: %(message)s')
        sh.setFormatter(sf)
        logger.addHandler(sh)

    if stdout:
        # create stream logger handler
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


def sec_log_call(a):

    parser = argparse.ArgumentParser(description='sample app with logging')
    parser.add_argument('-s', '--stdout', action='store_true', default=False, help='log to stdout')
    parser.add_argument('-r', '--rsyslog', action='store_true', default=False, help='log to syslog')
    parser.add_argument('-f', '--file', action='store_true', default=True, help='log file app.log')

    args = parser.parse_args()

    log = create_logger(
        app_name=APP_NAME,
        log_level=logging.DEBUG,
        syslog=args.rsyslog,
        stdout=args.stdout,
        file=args.file)
    log.debug(a)
    log.propagate = False
