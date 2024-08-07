import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://ping.domain.com   ->  Ping target
    #
    if "url" in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing url, specify as --url https://ping.domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        "User-Agent" : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    resp = requests.get(api_dict["proxy_url"], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuing. WARNING - This plugin is in beta and has not been rigorously tested!"

    return success, output, pluginargs
