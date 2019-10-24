#/usr/bin/python3

import logging
import xlsxwriter


logger = logging.getLogger('root')


def write_workbook(broadcast_stats_dict, outfile):
    """
    input: json object, outfile
    Read in json object then iterate over ssid's.
    - if the ssid's are in scope, add them to the first workseet
    - if not, the second worksheet
    """
    logger.info("Writing workbook: %s", outfile)
    workbook = xlsxwriter.Workbook(outfile)
    common_formatting = {'text_wrap': 1,'font_name': 'Arial', 'font_size': 10, 'align': 'center', 'valign': 'vcenter', 'border': 6, 'border_color': 'gray'}
    header = workbook.add_format({**common_formatting, 'bold': 1, 'bg_color': '#366092', 'font_color': 'white'})
    body = workbook.add_format(common_formatting)
    is_ws = workbook.add_worksheet('In Scope')
    oos_ws = workbook.add_worksheet('Out of Scope')
    is_row = 1
    oos_row = 1
    for ssid in broadcast_stats_dict:
        if broadcast_stats_dict[ssid][0]['in_scope'] is True:
            worksheet = is_ws
            row = is_row
        else:
            worksheet = oos_ws
            row = oos_row
        for i in broadcast_stats_dict[ssid]:
            logger.debug("ssid: '%s' row: %s ", ssid, row)
            # set proper height for each row
            worksheet.set_row(row, len(i['bssid'] * 14))
            _bssid = '\n'.join(i['bssid'])
            worksheet.write(row, 0, _bssid, body)
            worksheet.write(row, 1, ssid, body)
            if i['is_hidden']:
                worksheet.write(row, 2, 'Yes', body)
            else:
                worksheet.write(row, 2, '', body)
            worksheet.write(row, 3, i['channel'], body)
            worksheet.write(row, 4, i['encryption'], body)
            row += 1
            if broadcast_stats_dict[ssid][0]['in_scope'] is True:
                is_row += 1
            else:
                oos_row += 1
    # Define the layout.
    for worksheet in workbook.worksheets():
        worksheet.set_column(0, 0, 15)
        worksheet.set_column(1, 1, 25)
        worksheet.set_column(2, 2, 12)
        worksheet.set_column(3, 3, 9)
        worksheet.set_column(4, 4, 30)
        worksheet.write_row(0, 0, ['BSSID', 'SSID', 'Hidden SSID', 'Channel', 'Encryption'], header)
        if worksheet.get_name() is 'In Scope':
            last_row = is_row
        elif worksheet.get_name() is 'Out of Scope':
            last_row = oos_row
        worksheet.autofilter(0, 0, last_row, 4)
    workbook.close()