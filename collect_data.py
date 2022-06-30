import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import os
import whois
import jarowinkler
from datetime import date, datetime
import tldextract
from io import StringIO
import bs4
import ssl
import socket
import OpenSSL
import requests
import re
import csv
import validators
from bs4 import BeautifulSoup, SoupStrainer
from selenium import webdriver
from PIL import Image
import imagehash
import glob
from collections import defaultdict
from urllib.parse import urlparse

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "AppleWebKit/537.36 (KHTML, like Gecko)"
            "Chrome/78.0.3904.108 Safari/537.36"}


###############################################################
###                     Misc Function                       ###
###############################################################


srv = "https://554d-116-14-237-227.ngrok.io/"

def load_variables():
    r = requests.get(srv+"valid_sites.txt").text
    global valid_sites
    valid_sites = r

def fetch_tld_list() -> str:
    """
    :return:
    """
    r = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    if r.status_code == 200:
        tld_list = r.text
    return tld_list

def url_is_up(url: str) -> bool:
    """
    :param url:
    :return:
    """

    r = requests.head(url)
    return r.ok

def write_to_file(output, mode, line):
    """

    :param output:
    :param line:
    :return:
    """
    with open(output, mode, newline='') as file:
        mywriter = csv.writer(file, delimiter=';')
        mywriter.writerow(line)



###############################################################
###                     Content Function                    ###
###############################################################

def check_fake_login(url):
    """
    defunct func 1
    :param url:
    :return:
    """
    return 0


def check_sus_kw_index(url):
    """
    func 2
    :param url:
    :return:
    """
    try:
        # linkContent = requests.get(url, headers=headers, allow_redirects=False)
        linkContent = requests.get(url, headers=headers)

        ## this helps to see the history of redirects if allow_redirects is disabled ##
        # for resp in linkContent.history:
        #     print("TESTETSTEST", resp.status_code, resp.url)
        ## this helps to see the history of redirects if allow_redirects is disabled ##

        # print(linkContent)  # prints response code
        contentOut = linkContent.content.decode('utf-8').lower()
        # print(contentOut)  # prints content of site

        ## find specific words from whole website
        soup = BeautifulSoup(linkContent.content, 'html.parser')

        # kill all script and style elements
        for script in soup(["script", "style"]):
            script.extract()

        # get text
        text = soup.get_text()

        # break into lines and remove leading and trailing space on each line
        lines = (line.strip() for line in text.splitlines())

        # break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))

        # drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)

        print(text)

        ## finding patterns
        # note: need to always reupload urgent_wordlist.txt file loooool
        pattern_list = open("/content/urgent_wordlist.txt", "r", encoding='utf-8')
        for pattern_line in pattern_list:
            pattern.append(pattern_line.rstrip())
        # print(pattern)

        for urgentWords in pattern:
            if urgentWords in text:
                index.append(urgentWords)
            else:
                pass
        print(index)
    except Exception as e:
        print("Exception is: {}\n".format(e))
        return 0


def check_uptime_webpage(url):
    """
    defunct func 3 (see cronjob)
    :param url:
    :return:
    """
    return 0


def check_hyperlinks(url: str) -> dict:
    """
    Counts and return the amount of:
      1. Empty Hyperlinks
      2. External Hyperlinks
      3. Erroneous Hyperlinks
    func 4
    :param url:
    :return:
    """

    extract_main_url = tldextract.extract(url, include_psl_private_domains=True)
    domain_main_url = extract_main_url.domain

    r = requests.get(url)
    if r.status_code != 200:
        return 0

    content = r.content

    hyperlink_dict = defaultdict(int)
    empty_href_dict = defaultdict(int)
    external_href_dict = defaultdict(int)
    erroneous_href_dict = defaultdict(int)

    for link in BeautifulSoup(content, parse_only=SoupStrainer('a'), features='lxml'):
        if hasattr(link, "href"):
            href_link = link['href']

            # First Check: Is it empty?
            if href_link in ["", "#"]:
                empty_href_dict[href_link] += 1

            # Second Check: Is it an URL? If so, is it external?
            # If it isn't a URL, we're skipping it.
            else:
                if validators.url(href_link):
                    extract_href_url = tldextract.extract(href_link, include_psl_private_domains=True)
                    domain_href_url = extract_href_url.domain

                    if domain_href_url != domain_main_url:
                        external_href_dict[href_link] += 1

                    # Third Check: Is it an erroneous URL?
                    if url_is_up(href_link):
                        erroneous_href_dict[href_link] += 1

            # Append to the hyperlink list for possible future usage.
            hyperlink_dict[href_link] += 1

        return (
                sum(empty_href_dict.values()) +
                sum(external_href_dict.values()) +
                sum(erroneous_href_dict.values())
        )


###############################################################
###                     Domain Function                     ###
###############################################################


def is_registered(domain_name):
    try:
        registered = whois.whois(domain_name)
        return registered
    except:
        return False

def get_datetime(url):
    try:
        creation_date = url.get('creation_date')
        expire_date = url.get('expiration_date')
        if type(creation_date) != None and type(expire_date) != None:
            #print(type(creation_date))
            return creation_date, expire_date
    except AttributeError:
        return None

def calculate_datetime(creation_date, expire_date):
    diff = expire_date - creation_date
    return diff.days

def clean_datetime(_datetime):
    if type(_datetime) == list:
        _datetime = _datetime[0]
        #print(type(_datetime))
        return _datetime
    else:
        return _datetime

# check extended cert + CA rep
def get_cert_info(domain_name):
    context = ssl.SSLContext()
    try:
        # need to have a timeout here because it will iterate through as much domains that they find
        conn = socket.create_connection((domain_name, 443), timeout=5)
        sock = context.wrap_socket(conn, server_hostname=domain_name)
        sock.settimeout(5.0)
        #except (OSError, TypeError):
        #return ('Error2')

        #try:
        certificate = sock.getpeercert(True)
        pem_data = ssl.DER_cert_to_PEM_cert(certificate)
        pem_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data.encode('ascii'))
        issuer = pem_cert.get_issuer().CN
        _not_before_obj = datetime.datetime.strptime(pem_cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%S%z')
        _not_before = datetime.datetime.strftime(_not_before_obj, '%Y-%m-%d %H:%M:%S')
        _not_after_obj = datetime.datetime.strptime(pem_cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
        _not_after = datetime.datetime.strftime(_not_after_obj, '%Y-%m-%d %H:%M:%S')
        cert_start = datetime.datetime.fromisoformat(_not_before)
        cert_end = datetime.datetime.fromisoformat(_not_after)
        _scan_info = [cert_start, cert_end, issuer]
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return _scan_info
    except Exception as e:
        _dont_care = e


###############################################################
###                        URL Function                     ###
###############################################################

def check_IDN_Homograph(url: str) -> int:
    """
    func 10
    :param url:
    :return:
    """
    if not isinstance(url, str):
        return -1

    extract = tldextract.extract(url, include_psl_private_domains=True)
    domain = extract.domain

    return int(not (url.isascii()) or domain.startswith('xn--'))  # startswith vs contains/in? tbc



def check_subdomain_len(url: str) -> list:
    """
    func 11
    :param url:
    :return:
    """
    temp = {}
    subdomains = tldextract.extract(url, include_psl_private_domains=1).subdomain
    # for subdomain in subdomains.split("."):
    #     temp[subdomain] = len(subdomain)
    # return temp
    return len(subdomains.split("."))


def check_sub_TLD(url, tld_list):
    """
    func 12
    :param url:
    :param tld_list:
    :return:
    """
    subdomains = tldextract.extract(url).subdomain
    for subdomain in subdomains:
        if subdomain.casefold() in tld_list.casefold():  # Check each level of domain for TLD
            # print("TLD detected in subdomain")
            return 1
    return 0


def check_url_len(url):
    """
    func 13
    :param url:
    :return:
    """
    if len(url) > 54:
        return 1
    return 0


def check_hyphen_len(url):
    """
    func 14
    :param url:
    :return:
    """
    counter = 0
    subdomains = tldextract.extract(url).subdomain
    for char in subdomains:
        if char == "-":
            counter += 1
            if counter > 3:
                return 1
    return 0


###############################################################
###               Typoquatting Function                     ###
###############################################################


def check_jaro_distance(kw, domain):
    # Higher accuracy with all complete letters than missing
    # i.e transposition vs transformation
    # if value <0.5 then ignore. highly likely its some random url
    return jarowinkler.jaro_similarity(kw, domain)


def check_typosquatted_url(url):
    """
    func 15
    :param url:
    :return:
    """
    known_list = ["netflix", "apple", "amazon"]
    dist = 0
    for valid in known_list:
        curr = check_jaro_distance(valid, tldextract.extract(url).subdomain)
        if curr > dist:
            dist = curr
    if dist < 0.5:
        return 0
    return 1


def check_special_char(url):
    """
    func 16
    :param url:
    :return:
    """
    special_char = re.compile('[@=+*&]')  # add in special characters within the []

    # if have special characters
    if(special_char.search(url) != None):
        return 1
    else:
        return 0


def check_fake_www(url):
    """
    func 17
    :param url:
    :return:
    """
    subdomains = tldextract.extract(url).subdomain
    if "www." in subdomains:
        return 1
    return 0





def main():
    load_variables()
    df = pd.read_csv(srv + "Benign_list_big_final.csv")
    urls = df["url"]
    data = 0

    header = ["fake_login","sus_kw","uptime",
              "hyperlinks","CA_rep","extended_crt",
              "dns_exist","start_dns","end_dns",
              "IDN_homograph","subdomains","subTLD",
              "url_len","hyphen_len","typosquatted",
              "special_char","fake_www","misspelled"
        , "phishing_score"]
    write_to_file(r"D:\SIT\Y2T3\500benign.csv", "w", header)
    for url in urls:
        data += 1
        line = [None,None,None,
                None,None,None,
                None,None,None,
                None,None,None,
                None,None,None,
                None,None,None,
                0]
        print(url)

        line[0] = check_fake_login(url)
        # line[1] = check_sus_kw_index(url)
        line[1] = 0
        line[2] = check_uptime_webpage(url)
        # line[3] = check_hyperlinks(url)
        line[3] = 0
        record = is_registered(url)
        domain = urlparse(url).netloc
        try:
            domain_creation_date, domain_expire_date = get_datetime(record)
            domain_creation_date = clean_datetime(domain_creation_date)
            expire_date = clean_datetime(domain_expire_date)
            domain_duration = calculate_datetime(domain_creation_date, domain_expire_date)
            print('domain duration: %s' % (domain_duration))
            cert_info = get_cert_info(domain)
            cert_duration = calculate_datetime(cert_info[0], cert_info[1])
            print('cert duration: %s' % (cert_duration))
            # issuer = check_issuer(scan_info[2])
            print('issuer: %s' % (cert_info[2]))
        except TypeError:
            pass
        line[4] = check_CA_rep(url)
        line[5] = check_extended_crt(url)
        record = check_DNS_record(url)
        if record != 0:
            line[6] = 0
        line[7] = check_domain_reg_date(record)
        line[8] = check_end_DNS_record(record)
        line[9] = check_IDN_Homograph(url)
        line[10] = check_subdomain_len(url)
        tld_list = fetch_tld_list()
        line[11] = check_sub_TLD(url, tld_list)
        line[12] = check_url_len(url)
        line[13] = check_hyphen_len(url)
        line[14] = check_typosquatted_url(url)
        line[15] = check_special_char(url)
        line[16] = check_fake_www(url)
        # line[17] = check_misspelled_url(url)
        line[17] = 0
        try:
            line[18] = sum(line)
            print(line)
        except TypeError:
            print(f"sometime failed to return, ignoring url: {url}")
            pass

        if data == 500:
            return True
        # write_to_file(r"D:\SIT\Y2T3\500benign.csv", "a", line)


main()
