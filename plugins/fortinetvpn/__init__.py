import requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://domain.com    ->  gives the URL to the application
    # --domain DOMAIN              ->  Optional Input domain name
    #
    if 'url' in pluginargs.keys():
        if "https://" not in pluginargs['url'] and "http://" not in pluginargs['url']:
            error = "URL requires http:// or https:// prefix"
            return False, error, None
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    resp = requests.get(api_dict['proxy_url'] + "/remote/login?lang=en", headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    elif "fortinet" in resp.text:
        output = "Testconnect: Verified Fortinet instance, connected"
    else:
        output = "Testconnect: Warning, Fortinet client not indicated, continuting"

    return success, output, pluginargs
