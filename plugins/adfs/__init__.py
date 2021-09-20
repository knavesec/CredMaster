import requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://adfs.domain.com   ->  ADFS target
    #
    if 'url' in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://adfs.domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For": generate_ip(),
        "x-amzn-apigateway-api-id": generate_id(),
        "X-My-X-Amzn-Trace-Id": generate_trace_id(),
    }

    resp = requests.get(api_dict['proxy_url'], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuting"

    return success, output, pluginargs
