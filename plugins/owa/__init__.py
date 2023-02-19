import requests
import utils.utils as utils
from urllib.parse import urlparse
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

paths = {'OWA version 2003': '/exchweb/bin/auth/owaauth.dll',
         'OWA version 2007': '/owa/auth/owaauth.dll',
         'OWA version > 2007': '/owa/auth.owa'}


# check to see which owa endpoint is in use
def check_url(url):
    r = requests.get(url, verify=False)
    return r.status_code


def check_path(url):
    current_path = urlparse(url).path
    if not current_path or current_path == "/":
        srv = url.rstrip('/')   # just in case
        for key, value in paths.items():
            url_value = srv + value
            if check_url(url_value) == 200:
                output = f"Looks like {key}. Adding {value} to the end of the target"
                return value, output


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://mail.domain.com   ->  OWA mail target
    #
    if 'url' in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://mail.domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    url = api_dict['proxy_url']

    success = True
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    server_url = pluginargs['url']
    owa_url = check_path(pluginargs['url'])
    owa_server = url + owa_url[0].strip("/") # add the owa endpoint and eliminate double // at the end of the fireprox url

    resp = requests.get(url, headers=headers, verify=False)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Fingerprinting host... Internal Domain name: {domain}, continuing. " + owa_url[1]

    if success:
        domainname = utils.get_owa_domain(server_url, "/autodiscover/autodiscover.xml", useragent)
        output = output.format(domain=domainname)
        pluginargs['domain'] = domainname
        pluginargs['url'] = owa_server
        pluginargs['server_url'] = server_url # required for the payload in owa.py

    return success, output, pluginargs
