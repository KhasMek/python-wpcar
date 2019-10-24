#!/usr/bin/python3

import logging

from colorama import Fore, Style
from datetime import datetime


class ConsoleFormatter(logging.Formatter):

    FORMATS = {
        logging.DEBUG: Fore.CYAN  + " [~] (%(asctime)s) %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.GREEN  + " [-] (%(asctime)s) %(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW  + " [+] (%(asctime)s) %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + " [!] (%(asctime)s) %(message)s" + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + Style.BRIGHT + " [!] (%(asctime)s) %(message)s" + Style.RESET_ALL,
        "DEFAULT": " [ ] (%(asctime)s) %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


class FileFormatter(logging.Formatter):

    FORMATS = {
        logging.WARNING: "[WARN]\t(%(asctime)s) <%(module)s - %(filename)s:%(lineno)s - %(funcName)s> %(message)s",
        logging.CRITICAL: "[CRIT]\t(%(asctime)s) <%(module)s - %(filename)s:%(lineno)s - %(funcName)s> %(message)s",
        "DEFAULT": "[%(levelname)s]\t(%(asctime)s) <%(module)s - %(filename)s:%(lineno)s - %(funcName)s> %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)


def setup_logging(settings):
    """
    read in a json object of settings to set up the custom logging.
    """
    logger = logging.getLogger()
    # Set fallback/default log level.
    logger.setLevel('DEBUG')
    if 'console' in settings:
        logger_ch = logging.StreamHandler()
        logger_ch.setLevel(settings['console']['level'])
        logger_ch.setFormatter(ConsoleFormatter())
        logger.addHandler(logger_ch)
    if 'file' in settings:
        logger_fh = logging.FileHandler(settings['file']['filename'], mode='w')
        logger_fh.setLevel(settings['file']['level'])
        logger_fh.setFormatter(FileFormatter())
        logger.addHandler(logger_fh)
    logger.info('Logging set up successfully')
    return logger

