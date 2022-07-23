import tldextract
import jarowinkler
import re
from queue import Queue
from urllib.parse import urlparse
from datetime import datetime
import socket
import sys
import threading
from confusable_homoglyphs import confusables
from nostril import nonsense

from util import util

tld_list = util.fetch_tld_list()
brand_list = util.fetch_brand_list()

def check_IDN_Homograph(url: str) -> int:
    """
    :param url:
    :return:
    """
    if not isinstance(url, str):
        return -1

    # extract = tldextract.extract(url, include_psl_private_domains=True)
    # domain = extract.domain

    idn_homograph = bool(confusables.is_dangerous(url))
    if idn_homograph:
        return 1
    else:
        return 0


def check_subdomain_len(url: str) -> list:
    """
    :param url:
    :return:
    """
    temp = {}
    subdomains = tldextract.extract(url, include_psl_private_domains=1).subdomain
    # for subdomain in subdomains.split("."):
    #     temp[subdomain] = len(subdomain)
    # return temp
    return len(subdomains.split("."))


def check_sub_TLD(url):
    """
    :param url:
    :param tld_list:
    :return:
    """
    global tld_list

    tld_list = tld_list.lower()
    subdomains = tldextract.extract(url).subdomain
    subdomains = subdomains.split(".")
    for subdomain in subdomains:
        if subdomain.lower() in tld_list:  # Check each level of domain for TLD
            return 1
    return 0


def check_url_len(url):
    """
    :param url:
    :return:
    """
    if len(url) > 54:
        return 1
    return 0


def check_hyphen_len(url):
    """
    :param url:
    :return:
    """
    counter = 0
    extract = tldextract.extract(url)
    domain = extract.domain
    subdomains = extract.subdomain

    for char in domain:
      if char == "-":
          counter += 1

    for char in subdomains:
      if char == "-":
          counter += 1

    return counter


def check_jaro_distance(kw, domain):
    # Higher accuracy with all complete letters than missing
    # i.e transposition vs transformation
    # if value <0.5 then ignore. highly likely its some random url
    return jarowinkler.jaro_similarity(kw, domain)


def check_typosquatted_url(url):
    """
    :param url:
    :return:
    """
    global brand_list
    dist = 0
    for valid in brand_list:
        curr = check_jaro_distance(valid, tldextract.extract(url).subdomain)
        if curr > dist:
            dist = curr
    if dist < 0.5:
        return 0
    return 1


def check_special_char(url):
    """
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
    :param url:
    :return:
    """
    subdomains = tldextract.extract(url).subdomain
    subdomains = subdomains.split(".")
    if "www" in subdomains[1:]:
        return 1
    return 0

def check_fake_https(url):
    """
    :param url:
    :return:
    """
    subdomains = tldextract.extract(url).subdomain
    subdomains = subdomains.split(".")
    if "http" or "https" in subdomains[1:]:
        return 1
    return 0

def check_gibberish_url(url):
    """
    :param url:
    :return:
    """
    extract = tldextract.extract(url)
    domain = extract.domain
    subdomains = extract.subdomain
    indiv_subdomains = subdomains.split(".")
    
    try:
        if any(nonsense(x) for x in indiv_subdomains if len(x) >= 6) \
            or nonsense(subdomains) or nonsense(domain):
            return 1
    except Exception as e:
        pass

    return 0

def get_open_uncommon_ports(target):
    """
    :param target url:
    :return:
    """
    NUMBER_OF_THREADS = 100
    queue = Queue()

    # Get sub domain name (name.example.com)
    def get_sub_domain_name(target):
        global getWebsite
        try:
            link = urlparse(target).netloc
            if "www." in link:
                getWebsite = urlparse(target).netloc
                return getWebsite
            else:
                getWebsite = 'www.' + urlparse(target).netloc
                return getWebsite
        except:
            return ''


    def domain_name(target):
        try:
            results = get_sub_domain_name(target).split('.')
            return results[-2] + '.' + results[-1]
            # output = results[-2] + '.' + results[-1]
            # print(output)
        except:
            return ''

    domain_name(target)
    print(getWebsite)

    # Add Banner
    print("-" * 50)
    print("Scanning Target: " + getWebsite)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)

    portLister = []

    def tcp_scanner(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator
            result = s.connect_ex((getWebsite, port))
            if result == 0:
                print("Port {} is open".format(port))
                portLister.append(port)
                # print("list of ports:\n", portLister)
            s.close()

        except KeyboardInterrupt:
            print("\n Exiting Program")
            sys.exit()

        except socket.gaierror:
            print("\n Hostname Could Not Be Resolved")
            sys.exit()

        except socket.error:
            print("\n Server not responding")
            sys.exit()

    # Create worker threads (will die when main exits)
    def create_workers():
        for _ in range(NUMBER_OF_THREADS):
            t = threading.Thread(target=work)
            t.daemon = True
            t.start()

        for port in range(65535):
            queue.put(port)

        queue.join()

    # Do the next job in the queue
    def work():
        while True:
            port = queue.get()
            tcp_scanner(port)
            queue.task_done()

    create_workers()
    print("list of ports:\n", portLister)

    commonPorts = [20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443]

    for i in commonPorts:
        if i in portLister:
            portLister.remove(i)

    portLister.sort()
    print("remaining ports after removing common ports:\n", portLister)

    return len(portLister)