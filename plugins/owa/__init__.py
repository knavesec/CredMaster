import requests
from utils.utils import generate_ip, generate_id, generate_trace_id, get_owa_domain
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


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
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    resp = requests.get(url, headers=headers, verify=False)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Fingerprinting host... Internal Domain name: {domain}, continuing"

    if success:
        domainname = get_owa_domain(url, "/autodiscover/autodiscover.xml", useragent)
        output = output.format(domain=domainname)
        pluginargs['domain'] = domainname

    return success, output, pluginargs
