#/usr/bin/python3

import logging
import re
import subprocess
import tempfile


logger = logging.getLogger('root')


def run_aircrack(pcap, wordlist='', in_scope_networks=None, aircrackng_path='aircrack-ng', *args):
    for ssid in in_scope_networks:
        logger.info("Running aircrack against %s", ssid)
        cmd = [
            aircrackng_path,
            '-w', wordlist,
            '-e', ssid,
            pcap
        ]
        if args:
            for arg in args:
                cmd.append(arg)
        logger.debug(cmd)
        std = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        key = re.search(r'(KEY FOUND!)\s\[\s\w+\s\]', std.stdout, re.MULTILINE)
        if key:
            logger.warning('KEY FOUND: %s', key.group(0)[11:])
        elif 'No matching network found' in std.stdout:
            logger.info("No networks matching %s found in packet capture.", ssid)
        elif 'Passphrase not in dictionary' in std.stdout:
            logger.info("Passphrase for %s not in dictionary", ssid)
        elif 'Got no data packets from target network' in std.stdout:
            logger.info("Got no data packets for %s", ssid)
        else:
            for l in std.stdout.splitlines():
                logger.info("%s", l)


def create_hccapx(pcap, hccapx_path, cap2hccapx_path='cap2hccapx.bin'):
    logger.info("Creating hccapx: %s", hccapx_path)
    cmd = [
        cap2hccapx_path,
        pcap,
        hccapx_path
    ]
    std = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for l in std.stdout.splitlines():
        logger.debug(l)
        if l.startswith(' -->'):
            logger.info("Handshake Found:%s", l)
    if std.stderr:
        logger.info(std.stderr)


def manage_hashcat_output(std):
    try:
        keys = re.findall(r'\w+:\w+:\w+:\w+:\w+', std.stdout.decode('utf-8'))
    except UnicodeDecodeError:
        logger.debug('Hashcat spits out garbage from time to time, see below...')
        for l in "".join(map(chr, std.stdout)).splitlines():
            logger.debug(l)
        keys = ''
    if keys:
        for key in keys:
            logger.warning("Key Found: %s", key)


def run_hashcat(pcap, wordlist='', hash_modes='', hashcat_path='hashcat', **kwargs):
    """
    TODO:
      - filter by ssid (for create_hccapx())
      - add combo attacks
    """
    hccapx_path = tempfile.NamedTemporaryFile()
    create_hccapx(pcap, hccapx_path.name)
    potfile_path = tempfile.NamedTemporaryFile()
    for hash_mode in hash_modes:
        # note: hccapx_path.name and wordlist have to be the last two values.
        cmd = [
            hashcat_path,
            '-m', str(hash_mode),
            '-a', '0',
            '--potfile-path', potfile_path.name,
            '--quiet',
            hccapx_path.name,
            wordlist
        ]
        if 'hashcat_args' in kwargs and kwargs['hashcat_args'] is not None:
            for arg in kwargs['hashcat_args']:
                logger.debug("Adding arg `%s` to hashcat command.", arg)
                cmd.insert(-2, arg)
        logger.info("Running: `%s`", ' '.join(cmd))
        std = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        manage_hashcat_output(std)
        if 'rules' in kwargs and kwargs['rules'] is not None:
            logger.debug("HASHCAT RULES FOUND")
            for rule in kwargs['rules']:
                potfile = tempfile.NamedTemporaryFile()
                rules_cmd = cmd + ['-r', rule, '--potfile-path', potfile.name]
                logger.info("Running: `%s`", ' '.join(rules_cmd))
                std = subprocess.run(rules_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                manage_hashcat_output(std)
        if 'mask_attacks' in kwargs and kwargs['mask_attacks'] is not None:
            logger.debug("HASHCAT MASK ATTACKS FOUND")
            for mask_attack in kwargs['mask_attacks']:
                potfile = tempfile.NamedTemporaryFile()
                mask_cmd = cmd + ['--potfile-path', potfile.name]
                # Switch modes
                mask_cmd[4] = '3'
                mask_cmd[6] = mask_attack
                logger.info("Running: `%s`", ' '.join(mask_cmd))
                std = subprocess.run(mask_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                manage_hashcat_output(std)
