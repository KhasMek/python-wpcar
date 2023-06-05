#/usr/bin/python3

import os
import logging
import pyshark
import re
import subprocess
import sys
import tempfile
import binascii

from colorama import Fore, Style
from datetime import datetime
from tqdm import tqdm


logger = logging.getLogger('root')


def get_pcap_type(pcap):
    capture_type = set()
    for i in pcap:
        if i.endswith('pcap'):
            capture_type.add('pcap')
        elif i.endswith('pcapng'):
            capture_type.add('pcapng')
    if len(capture_type) > 1:
        logger.critical("Directory contains a mixture of pcap and pcapng files! \
                This is not currently supported. Quitting...")
        sys.exit()
    return capture_type.pop()


def merge_pcaps(path, outfile, mergcap_path='mergecap'):
    """
    path can be a directory, string of files, or list of files
    """
    capture_type = get_pcap_type(path)
    if type(path) is str:
        cmd = [
            mergcap_path,
            '-F',
            capture_type,
            '-w',
            outfile,
            path
        ]
    if type(path) is list:
        cmd = [
            mergcap_path,
            '-F',
            capture_type,
            '-w',
            outfile
        ]
        for p in path:
            cmd.append(p)
    (cmd)
    subprocess.run(cmd)


def parse_pcap(pcap_path, broadcast_stats_list, display_filter=''):
    """
    # TODO: count more stats like number of packets, auth/deauth packets, etc.
    """
    num_pkts = get_pcap_length(pcap_path)
    logger.info("%s packets in %s", str(num_pkts), pcap_path)
    pcap = pyshark.FileCapture(pcap_path, keep_packets=False, display_filter=display_filter)
    pkt_num = 0
    ssids_processed = 0
    bar_format = Fore.GREEN  + \
                " [ ] ({elapsed}<{remaining}) [{rate_fmt}] {n_fmt}/{total_fmt} {l_bar}{bar}|" + \
                Style.RESET_ALL
    with tqdm(range(num_pkts), bar_format=bar_format, unit='pkts') as pbar:
        for pkt in enumerate(pcap):
            broadcast_stats = get_broadcast_stats(pkt[1])
            if broadcast_stats and broadcast_stats not in broadcast_stats_list:
                broadcast_stats_list.append(broadcast_stats)
                ssids_processed += 1
            pbar.update()
            pkt_num += 1
    logger.debug("broadcast_stats_list: %s", broadcast_stats_list)
    pcap.close()
    if pkt_num > num_pkts:
        logger.warning("More packets were processed than expected!")
    logger.info("Total Processed Packets: %s", pkt_num)
    logger.info("%s packets proccessed across %s devices", pkt_num, ssids_processed)


def pcapng_to_pcap(infile, outfile=tempfile.NamedTemporaryFile().name):
    cmd = [
        'tshark',
        '-F', 'pcap',
        '-r', infile,
        '-w', outfile
    ]
    logger.debug("Running command `%s`", ' '.join(cmd))
    std = subprocess.run(cmd, stderr=subprocess.PIPE)
    if not std.stderr:
        logger.debug("Pcap %s successfully created", outfile)
        return outfile

def is_hex_colon(test):
    pattern = r'^([0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}$'
    match = re.match(pattern, test)
    return match is not None

def get_broadcast_stats(pkt):
    ssid = ''
    channel = '0'
    ssid_hidden = True
    encryption = None
    if int(pkt.wlan.fc_type) == 0:
        if int(pkt.wlan.fc_subtype) == 8:
            bssid = str(pkt.wlan.bssid)
            logger.debug("BSSID: %s", bssid)
            for layer in pkt.layers:
                if 'wlan_ssid' in layer.field_names:
                    ssid = layer.wlan_ssid
                    logger.debug("SSID Before: %s", str(ssid))
                    if is_hex_colon(ssid):
                        ssid = ssid.replace(':', '')
                        bytes_data = binascii.unhexlify(ssid)
                        ssid = bytes_data.decode('ascii', errors='replace')
                    logger.debug("SSID: %s", str(ssid))
                if 'wlan_ds_current_channel' in layer.field_names:
                    logger.debug("Channel: %s", layer.wlan_ds_current_channel)
                    channel = int(layer.wlan_ds_current_channel)
                if 'wlan_fixed_capabilities_privacy' in layer.field_names:
                    logger.debug("Encryption: %s", layer.wlan_fixed_capabilities_privacy)
                    if int(layer.wlan_fixed_capabilities_privacy) == 0:
                        encryption = None
                    else:
                        encryption = get_encryption(pkt)
                    logger.debug("Encryption: %s", encryption)
            if ssid.startswith("SSID:"):
                ssid = ''
            if ssid != '':
                ssid_hidden = False
            else:
                ssid_hidden = True
            return [ bssid, ssid, ssid_hidden, channel, encryption ]


def get_encryption(pkt):
    """
    get sent a packet through get_broadcast_stats and return
    the entire encrption cipher suite.
    """
    privacy = ''
    cipher = ''
    auth = ''
    for layer in pkt.layers:
        if 'wlan_rsn_pcs_list' in layer.field_names:
            pcs = str(' '.join(re.findall(r'(AES \(CCM\)|TKIP)', layer.wlan_rsn_pcs_list)))
            privacy = pcs.replace('AES (CCM)', 'CCMP')
            if "CCMP" and "TKIP" in privacy:
                cipher = "WPA2 WPA"
            elif "CCMP" in privacy:
                cipher = "WPA2"
            elif "TKIP" in privacy:
                cipher = "WPA"
        if 'wlan_rsn_akms_list' in layer.field_names:
            # TODO: I need to test this more for other suites but it seems good.
            akms = str(' '.join(re.findall(r'PSK', layer.wlan_rsn_akms_list)))
            if akms:
                auth = akms
            else:
                auth = ''
    encryption = str("{}+{}+{}".format(cipher, privacy, auth))
    # Could use some smrtr logic
    if encryption == '++':
        for layer in pkt.layers:
            if 'wlan_fixed_capabilities_privacy' in layer.field_names and int(layer.wlan_fixed_capabilities_privacy) == 1:
                encryption = str("WEP")
    return encryption


def get_pcap_length(pcap_path, display_filter=''):
    """
    We use enumerate instead of pcap.load_packets() because load_packets will eat all of your
    RAM on larger packets.
    """
    pcap = pyshark.FileCapture(pcap_path, display_filter=display_filter, only_summaries=True)
    pcap_len = ''
    logger.info("Checking the size of packet capture file. This may take a while...")
    for pkt in enumerate(pcap):
        pcap_len = pkt[0]
    pcap.close()
    # TODO: it seems like the latest tshark is not counting all the way to the end of the pcap (hence the +2)???
    return pcap_len + 2


def check_is_pcap(pcap):
    pcap = os.fsdecode(pcap)
    if pcap.endswith(".pcap") or pcap.endswith(".pcapng"):
        return True
    else:
        return False
