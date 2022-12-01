import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://mail.domain.com   ->  EWS mail target
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

    resp = requests.get(url, headers=headers, verify=False)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Fingerprinting host... Internal Domain name: {domain}, continuing"

    if success:
        domainname = utils.get_owa_domain(url, "/ews/", useragent)
        output = output.format(domain=domainname)
        pluginargs['domain'] = domainname

    return success, output, pluginargs
