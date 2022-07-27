import pandas as pd
import csv

from features import content, url_analysis
from util import util

import requests

number = -1

def go_next() -> int:
    global number
    number += 1
    return number

def main():
    global number

    # Variables / FPs
    export_csv_fp = 'clustered.csv'

    # Initialize the new columns
    columns = util.prepare_columns()
    columns.insert(0, 'url')
    url_list = []

    # Get URL List from OpenPhish
    url_list_url = "https://openphish.com/feed.txt"
    r = requests.get(url_list_url)
    if r.status_code == 200:
        for i, line in enumerate(r.text.split('\n')):
            url_list.append(line) 
    else: 
        return 0

    with open(export_csv_fp, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        # Iterate websites
        for index, url in enumerate(url_list):
            number = -1
            row = [None for i in range(0, len(columns))]
            row[go_next()] = url
            row[go_next()], row[go_next()], \
                row[go_next()], row[go_next()], \
                    row[go_next()], row[go_next()], \
                        row[go_next()] \
                        = content.content_analysis(url)
            
            row[go_next()] = url_analysis.check_IDN_Homograph(url)
            row[go_next()] = url_analysis.check_subdomain_len(url)
            row[go_next()] = url_analysis.check_sub_TLD(url)
            row[go_next()] = url_analysis.check_url_len(url)
            row[go_next()] = url_analysis.check_hyphen_len(url)
            row[go_next()] = url_analysis.check_typosquatted_url(url)
            row[go_next()] = url_analysis.check_special_char(url)
            row[go_next()] = url_analysis.check_fake_www(url)
            row[go_next()] = url_analysis.check_gibberish_url(url)

            writer.writerow(row)

if __name__ == '__main__':
    main()