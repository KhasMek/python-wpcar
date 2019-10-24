#/usr/bin/python3

import csv
import json
import logging
import yaml


from wpcar.xlsx import write_workbook


logger = logging.getLogger('root')


def write_csv(broadcast_stats_list, outfile):
    with open(outfile, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["ssid", "bssid", "Hidden", "Channel", "Encryption"])
        writer.writerows(broadcast_stats_list)


def write_json(broadcast_stats_dict, outfile):
    with open(outfile, 'w') as f:
        json.dump(broadcast_stats_dict, f, indent=4, sort_keys=True)


def write_reports(reports, broadcast_stats_dict, broadcast_stats_list):
    for _type in reports:
        if 'json' in _type:
            write_json(broadcast_stats_dict, reports['json'])
        elif 'xlsx' in _type:
            write_workbook(broadcast_stats_dict, reports['xlsx'])
        elif 'csv' in _type:
            write_csv(broadcast_stats_list, reports['csv'])
        else:
            logger.warning("Unknown or unsupported file type: %s!",_type)


def read_config(config_file):
    with open(config_file, 'r') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
        logger.debug(section for section in config)
        return config


def sort_scope(broadcast_stats, whitelist='', merge_blacklist=''):
    """
    This looks at if there's a whitelist/blacklist and sorts a scope based on
    those variables.
    scope {
        ssid1 [{
            in_scope: True,
            is_hidden: False,
            channel: 11,
            encryption: 'WPA2+CCMP+PSK',
            bssid: [
                xx:xx:xx:xx:xx:x1,
                xx:xx:xx:xx:xx:x2
            ]
        },
        {
            in_scope: True,
            is_hidden: False,
            channel: 6,
            encryption: 'WPA2+CCMP+PSK',
            bssid: [
                xx:xx:xx:xx:xx:x13
            ]
        }]
    }
    """
    broadcast_dict = {}
    for stat in broadcast_stats:
        ssid = stat[1]
        logger.debug("processing %s", stat)
        if ssid in whitelist:
            is_in_scope = True
            logger.debug("%s in whitelist", ssid)
        else:
            is_in_scope = False
            logger.debug("ssid '%s' not in whitelist", ssid)
        if ssid not in broadcast_dict:
            logger.debug("ssid '%s' not in broadcast_dict, adding now", ssid)
            broadcast_dict[ssid] = [{
                'in_scope': is_in_scope,
                'is_hidden': stat[2],
                'channel': stat[3],
                'encryption': stat[4],
                'bssid': [stat[0]]
            }]
        else:
            logger.debug("ssid '%s' in broadcast_dict, comparing all values now", ssid)
            _nfi = []
            logger.debug("broadcast_dict: '%s'", broadcast_dict[ssid])
            for x in broadcast_dict[ssid]:
                logger.debug("Checking for '%s' in broadcast_dict[ssid]", x)
                _nfi.append(x['bssid'])
            if stat[0] not in _nfi:
                logger.debug("bssid '%s' not in broadcast_dict['ssid']['bssid'] list, comparing channels, hidden and encryption", stat[0])
                _stat_added = False
                for x in broadcast_dict[ssid]:
                    logger.debug("comparing stats %s and x %s", stat, x)
                    _hidden_match =  False
                    _channel_match =  False
                    _encryption_match = False
                    # Extra check for ssid's you don't want to merge, jic.
                    if merge_blacklist and str(ssid) not in merge_blacklist:
                        # Don't merge hidden SSID's.
                        if stat[2] is x['is_hidden'] and stat[2] is False:
                            _hidden_match = True
                            logger.debug("Encryption '%s' is in x['is_hidden'] %s and is False", stat[2], x['is_hidden'])
                        else:
                            logger.debug("Encryption '%s' is not in x['is_hidden'] %s or is True", stat[2], x['is_hidden'])
                        if stat[3] is x['channel']:
                            _channel_match = True
                            logger.debug("Channel %s is in x['channel'] %s", stat[3], x['channel'])
                        else:
                            logger.debug("Channel %s is not in x['channel'] %s", stat[3], x['channel'])
                        if str(stat[4]) in str(x['encryption']):
                            _encryption_match = True
                            logger.debug("Encryption '%s' is x['encryption'] %s", stat[4], x['encryption'])
                        else:
                            logger.debug("Encryption '%s' is not x['encryption'] %s", stat[4], x['encryption'])
                        logger.debug("ssid: '%s'", str(ssid))
                        if _hidden_match and _channel_match and _encryption_match:
                            x['bssid'].append(stat[0])
                            logger.debug("Added: %s to %s", stat[0], x)
                            _stat_added = True
                if not _stat_added:
                    logger.debug("Stat %s does not match", stat[0])
                    broadcast_dict[ssid].append({
                                        'in_scope': is_in_scope,
                                        'is_hidden': stat[2],
                                        'channel': stat[3],
                                        'encryption': stat[4],
                                        'bssid': [stat[0]]
                                    })
            else:
                logger.debug("bssid is already in broadcast_dict['ssid']['bssid'] list, skipping")
    return broadcast_dict



def append_to_list(pcap_stats, stats_list):
    if type(pcap_stats) is not "tuple":
        logger.error("%s is a %s and not tuple.\nAttempting to convert", pcap_stats, type(pcap_stats))
        pcap_stats = tuple(pcap_stats)
    if pcap_stats not in stats_list:
        stats_list.append(pcap_stats)
