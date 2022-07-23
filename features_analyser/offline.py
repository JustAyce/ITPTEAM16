import pandas as pd
import csv
import os

from features import content, url_analysis
from util import util

# Disable Warning
# https://stackoverflow.com/questions/20625582/how-to-deal-with-settingwithcopywarning-in-pandas
pd.options.mode.chained_assignment = None 

number = -1

def go_next() -> int:
    global number
    number += 1
    return number

def main():
    global number

    # Variables / FPs
    phishing_kit_fp = os.path.join(os.sep, 'home', 'user', 'Desktop', 'Sample', '2022')
    clustered_csv_fp = 'clustered.csv'
    export_csv_fp = 'cluster_with_features.csv'
    
    # Open clustered.csv
    df = pd.read_csv(clustered_csv_fp, sep=',')

    # Initialize the new columns
    columns = util.prepare_columns()
    for column in columns:
        df[column] = ''

    # Iterate websites
    for index in df.index:
        index_fp = ""
        number = -1
        row = [None for i in range(0, len(columns))]
        url = df['website'][index]
        index_fp = os.path.join(phishing_kit_fp, df['index_fp'][index])

        # Content Analysis
        #: sus_kw, hyperlinks_count, \
        #: ext_empty_hyperlinks_count, image_count \
        #: img_external_request_url_count, external_favicon \
        #: domain_not_in_title
        df[columns[go_next()]][index], df[columns[go_next()]][index], \
            df[columns[go_next()]][index], df[columns[go_next()]][index], \
                df[columns[go_next()]][index], df[columns[go_next()]][index], \
                    df[columns[go_next()]][index] \
                    = content.content_analysis_offline(url, index_fp)

        # URL Analysis
        #: idn_homograph, no_of_subdomains, tld_as_subdomain, url_len, \
        #: hyphen_count, typosquatted_url,   special_chars_in_url, www_in_url \
        #: gibberish_url
        df[columns[go_next()]][index] = url_analysis.check_IDN_Homograph(url)
        df[columns[go_next()]][index] = url_analysis.check_subdomain_len(url)
        df[columns[go_next()]][index] = url_analysis.check_sub_TLD(url)
        df[columns[go_next()]][index] = url_analysis.check_url_len(url)
        df[columns[go_next()]][index] = url_analysis.check_hyphen_len(url)
        df[columns[go_next()]][index] = url_analysis.check_typosquatted_url(url)
        df[columns[go_next()]][index] = url_analysis.check_special_char(url)
        df[columns[go_next()]][index] = url_analysis.check_fake_www(url)
        df[columns[go_next()]][index] = url_analysis.check_gibberish_url(url)

    # Export New DataFrame to csv
    df.to_csv(export_csv_fp)

if __name__ == '__main__':
    main()