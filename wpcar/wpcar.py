#/usr/bin/python3

import json
import logging
import os
import tempfile

from datetime import datetime
from wpcar.cracking import run_aircrack, run_hashcat
from wpcar.helpers import read_config, sort_scope, write_reports
from wpcar.logging import setup_logging
from wpcar.pcap import check_is_pcap, merge_pcaps, parse_pcap, pcapng_to_pcap
from wpcar.xlsx import write_workbook


logger = ''


def run_modules(pcap_path, config, broadcast_stats_list):
    """
    Read in all of the config settings and run the necessary modules.
    """
    if 'parse_pcap' in config and config['parse_pcap']:
        logger.info("Parsing Pcap")
        parse_pcap(pcap_path, broadcast_stats_list, config['display_filter'])
        broadcast_stats_dict = sort_scope(broadcast_stats_list, config['in_scope_networks'], config['merge_blacklist'])
        if 'reports' in config:
            write_reports(config['reports'], broadcast_stats_dict, broadcast_stats_list)
    if 'enabled' in config['aircrack-ng'] and config['aircrack-ng']['enabled']:
        # Parse options - global first, then "local"
        if 'wordlist' in config['aircrack-ng']:
            wordlist_path = config['aircrack-ng']['wordlist_path']
        else:
            wordlist_path = config['wordlist_path']
        if 'in_scope_networks' in config['aircrack-ng']:
            in_scope_networks = config['aircrack-ng']['in_scope_networks']
        else:
            in_scope_networks = config['in_scope_networks']
        if 'path' in config['aircrack-ng']:
            aircrackng_path = config['aircrack-ng']['path']
        else:
            aircrackng_path = 'aircrack-ng'
        aircrack_args = None
        if 'args' in config['aircrack-ng'] and config['aircrack-ng']['args'] is not None:
            aircrack_args = config['aircrack-ng']['args']
            run_aircrack(pcap_path, wordlist_path, in_scope_networks, aircrackng_path, aircrack_args)
        else:
            run_aircrack(pcap_path, wordlist_path, in_scope_networks, aircrackng_path)
    if'enabled' in config['hashcat'] and config['hashcat']['enabled']:
        if 'wordlist' in config['hashcat']:
            wordlist_path = config['hashcat']['wordlist_path']
        else:
            wordlist_path = config['wordlist_path']
        if 'hash_modes' in config['hashcat']:
            hash_modes = config['hashcat']['hash_modes']
        else:
            hash_modes = []
        if 'hashcat_path' in config['hashcat']:
            hashcat_path = config['hashcat']['hashcat_path']
        else:
            hashcat_path = 'hashcat'
        if 'cap2hccapx_path' in config['hashcat']:
            cap2hccapx_path = config['hashcat']['cap2hccapx_path']
        else:
            cap2hccapx_path = 'cap2hccapx.bin'
        if 'rules' in config['hashcat'] and len(config['hashcat']['rules']) > 0:
            rules = config['hashcat']['rules']
            logger.debug(rules)
        else:
            rules = None
        if 'mask_attacks' in config['hashcat'] and len(config['hashcat']['mask_attacks']) > 0:
            mask_attacks = config['hashcat']['mask_attacks']
            logger.debug(mask_attacks)
        else:
            mask_attacks = None
        if 'args' in config['hashcat'] and config['hashcat']['args'] is not None:
            hashcat_args = config['hashcat']['args']
        else:
            hashcat_args = None
        run_hashcat(pcap_path, wordlist_path, hash_modes, hashcat_path, rules=rules, mask_attacks=mask_attacks, hashcat_args=hashcat_args)


def main():
    global logger
    config = read_config('config.yaml')
    logger = setup_logging(config['logging'])
    logger.warning("Starting analysis, this may take a while...")
    pcap_path = config['pcap_path']
    logger.info("pcap_path: %s", pcap_path)
    logger.info("In scope networks: %s", ', '.join(config['in_scope_networks']))
    start_time = datetime.now()
    broadcast_stats_list = []
    if os.path.exists(pcap_path) and os.path.isdir(pcap_path):
        pcap_paths = []
        logger.debug("pcap_path is a directory")
        for filepath in os.listdir(pcap_path):
            f = os.fsdecode(filepath)
            if f.endswith(".pcap") or f.endswith(".pcapng"):
                pcap_paths.append(os.path.join(pcap_path, f))
            else:
                logger.warning("File %s does not end in pcap or pcapng. Skipping...", f)
        if len(pcap_paths) > 1:
            logger.info("Merging pcaps into one file for processing and analysis.")
            pcap_path = tempfile.NamedTemporaryFile().name
            merge_pcaps(pcap_paths, pcap_path)
        else:
            pcap_path = pcap_paths[0]
        if pcap_path.endswith(".pcapng") and ('aircrack-ng' or 'hashcat') in config:
            logger.warning("Aircrack-ng/Hashcat do not support pcapng files, converting to pcap now...")
            pcap_path = pcapng_to_pcap(pcap_path, tempfile.NamedTemporaryFile().name)
        run_modules(pcap_path, config, broadcast_stats_list)
    elif os.path.exists(pcap_path) and os.path.isfile(pcap_path):
        logger.debug("pcap_path is a file")
        if check_is_pcap(pcap_path):
            if pcap_path.endswith(".pcapng") and ('aircrack-ng' or 'hashcat') in config:
                logger.warning("Aircrack-ng/Hashcat do not support pcapng files, converting to pcap now...")
                pcap_path = pcapng_to_pcap(pcap_path)
            run_modules(pcap_path, config, broadcast_stats_list)
        else:
            logger.warning("File {} does not end in pcap or pcapng. Skipping...")
    else:
        logger.critical("%s does not exist! Exiting...", pcap_path)
    end_time = datetime.now()
    logger.info("TOOK %s", end_time - start_time)
    logger.info("Analysis completed.")
