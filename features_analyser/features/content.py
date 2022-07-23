import requests
from bs4 import BeautifulSoup, SoupStrainer
import tldextract
from collections import defaultdict
import validators
import re
from pathlib import Path

from urllib3.exceptions import InsecureRequestWarning
# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

from util import util

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "AppleWebKit/537.36 (KHTML, like Gecko)"
            "Chrome/78.0.3904.108 Safari/537.36"}

sus_kw_list = util.fetch_sus_kw_list()

def content_analysis(url):
    try:
      url = util.clean_url_for_requests(url)
      resp = requests.get(url, timeout=5, verify=False)
    except Exception as e:
      print(e)
      return 0, 0, 0, 0, 0, 0, 0

    content = resp.content 

    hyperlinks_count, ext_empty_hyperlinks_count = check_hyperlinks(url, content)
    img_count, img_external_request_url_count = check_img(url, content)

    return check_sus_kw(content), hyperlinks_count, \
    ext_empty_hyperlinks_count, img_count, img_external_request_url_count, \
      check_external_favicon(url, content), check_domain_not_in_title(url, content)

def content_analysis_offline(url, index_fp):
    try:
      #with open(index_fp, 'r') as content:
      content = Path(index_fp).read_text(encoding='unicode_escape')#errors='ignore')
      # Pre-parse php to remove all PHP elements
      content = re.sub(r'<\?php.*?\?>', "", str(content), flags=re.S+re.M)

      hyperlinks_count, ext_empty_hyperlinks_count = check_hyperlinks(url, content)
      img_count, img_external_request_url_count = check_img(url, content)

      return check_sus_kw(content), hyperlinks_count, \
      ext_empty_hyperlinks_count, img_count, img_external_request_url_count, \
        check_external_favicon(url, content), check_domain_not_in_title(url, content)

    except Exception as e:  
      print(e)
      return 0, 0, 0, 0, 0, 0, 0

def check_sus_kw(content) -> int:
    """
    :param url:
    :return:
    """
    global sus_kw_list

    try:
      kw_detected = []

      #contentOut = resp.content.decode('utf-8').lower()
      soup = BeautifulSoup(content, 'html.parser')

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

      for sus_kw in sus_kw_list:
        if sus_kw in text:
          kw_detected.append(sus_kw)

      return len(kw_detected)
    except Exception as e:
      print("Exception is: {}\n".format(e))
      return 0

def check_hyperlinks(url: str, content) -> tuple[int, int]:
    """
    Counts and return the total number of hyperlinks, and the sum of:
      1. Empty Hyperlinks
      2. External Hyperlinks
      3. Erroneous Hyperlinks [Removed]
    :return:
    """

    extract_main_url = tldextract.extract(url, include_psl_private_domains = True)
    domain_main_url = extract_main_url.domain

    hyperlink_dict = defaultdict(int)
    empty_href_dict = defaultdict(int)
    external_href_dict = defaultdict(int)
    #erroneous_href_dict = defaultdict(int)

    for link in BeautifulSoup(content, parse_only=SoupStrainer('a'), features='lxml'):
      if hasattr(link, "href"):
        href_link = link.get('href')

        # First Check: Is it empty?
        if href_link in ["", "#"]:
          empty_href_dict[href_link] += 1

        # Second Check: Is it an URL? If so, is it external? 
        # If it isn't a URL, we're skipping it.
        elif href_link is not None:
          if validators.url(str(href_link)):
            extract_href_url = tldextract.extract(href_link, include_psl_private_domains = True)
            domain_href_url = extract_href_url.domain

            if domain_href_url != domain_main_url:
              external_href_dict[href_link] += 1

            # # Third Check: Is it an erroneous URL? [Removed]
            # if util.url_is_up(href_link):
            #   erroneous_href_dict[href_link] += 1

        # Append to the hyperlink list for possible future usage.
        hyperlink_dict[href_link] += 1
    return sum(hyperlink_dict.values()), \
      sum(empty_href_dict.values()) + \
      sum(external_href_dict.values()) \
      #sum(erroneous_href_dict.values())

def check_img(url: str, content) -> tuple[int, int]:
    extract_main_url = tldextract.extract(url, include_psl_private_domains = True)
    domain_main_url = extract_main_url.domain
    img_external_request_url_count = 0

    soup = BeautifulSoup(content, features='lxml')
    images = soup.findAll('img')
    if images:
      for img in images:
        img_src = img.get('src')

        # Check: Is it an URL? If so, is it external? 
        if validators.url(str(img_src)):
          extract_href_url = tldextract.extract(img_src, include_psl_private_domains = True)
          domain_href_url = extract_href_url.domain

          if domain_href_url != domain_main_url:
            img_external_request_url_count += 1
        
      return len(images), img_external_request_url_count
    
    return 0, 0

def check_external_favicon(url: str, content) -> int:
    extract_main_url = tldextract.extract(url, include_psl_private_domains = True)
    domain_main_url = extract_main_url.domain

    soup = BeautifulSoup(content, features='lxml')
    icon_link = soup.find("link", attrs={'rel': re.compile("^(shortcut icon|icon)$", re.I)})

    if icon_link:
      href = icon_link.get('href')
      if validators.url(href):
        extract_href_url = tldextract.extract(href, include_psl_private_domains = True)
        domain_href_url = extract_href_url.domain

        if domain_href_url != domain_main_url:
          return 1

    return 0

def check_domain_not_in_title(url: str, content):
    soup = BeautifulSoup(content, features='lxml')
    title = soup.find('title')

    if title:
      title_context = title.string
      if title_context:
        title_context = title_context.split(' ')
        if not any(title_word.lower() in url for title_word in title_context): 
          return 1

    return 0