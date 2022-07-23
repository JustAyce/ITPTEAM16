import requests
from urllib.parse import urlparse

def fetch_sus_kw_list() -> list:
    """
    :return:
    """
    sus_kw_list = []
    r = requests.get("https://raw.githubusercontent.com/JustAyce/ITPTEAM16/main/wordlists/urgent_wordlist.txt")
    if r.status_code == 200:
        data = r.text
        for i, line in enumerate(data.split('\n')):
            sus_kw_list.append(line)

    return sus_kw_list

def fetch_tld_list() -> str:
    """
    :return:
    """
    tld_list = ''
    r = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    if r.status_code == 200:
        tld_list = r.text
    return tld_list

def fetch_brand_list() -> str:
    """
    :return:
    """
    brand_list = []
    r = requests.get("https://raw.githubusercontent.com/JustAyce/ITPTEAM16/main/wordlists/brand_names.txt")
    if r.status_code == 200:
        data = r.text
        for i, line in enumerate(data.split('\n')):
            brand_list.append(line)

    return brand_list
    
def clean_url_for_requests(url: str) -> str:
    """
    :param url:
    :return:
    """
    p = urlparse(url); 
    return f"{p.scheme}://{p.netloc}"

def url_is_up(url: str) -> bool:
    """
    :param url:
    :return:
    """
    r = None
    try:
        r = requests.get(url)
    except:
        return False
    return r.ok

def prepare_columns():
    column = ["sus_kw","hyperlinks_count", "ext_empty_hyperlinks_count", 
    "image_count", "img_external_request_url_count", "external_favicon",
    "domain_not_in_title",
    #"no_dns_record", "dns_duration", "cert_duration", "less_rep_CA", 
    "IDN_homograph","subdomains", "subTLD", "url_len","hyphen_len",
    "typosquatted", "special_char","fake_www",
    "gibberish_url"
    ] #,"uncommon_ports"]

    return column