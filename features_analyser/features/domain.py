import whois
import ssl
import socket
import OpenSSL
import datetime
from urllib.parse import urlparse

def is_registered(domain_name):
  try:
    registered = whois.whois(domain_name)
    return registered
  except Exception as e:
    print(e)
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
    print(f'debug exception {e}')

def check_domain_and_tls(url):#will use if checking issuer is R3
    """
    :param url:
    :return:
    """
    whois_obj = is_registered(url)
    if whois_obj:
      try:
        domain = urlparse(url).netloc
        domain_creation_date, domain_expire_date = get_datetime(whois_obj)
        domain_creation_date = clean_datetime(domain_creation_date)
        domain_expire_date = clean_datetime(domain_expire_date)
        domain_duration = calculate_datetime(domain_creation_date, domain_expire_date)
        print('domain duration: %s' % (domain_duration))
        cert_info = get_cert_info(domain)
        cert_duration = calculate_datetime(cert_info[0], cert_info[1])
        print('cert duration: %s' % (cert_duration))

        issuer = cert_info[2]
        print('issuer: %s' % (issuer))
        return 0, domain_duration, cert_duration, int(issuer == 'R3')
      except Exception as e:
        print(e)
        return 1, 0, 0, 0
    
    else:
      return 1, 0, 0, 0