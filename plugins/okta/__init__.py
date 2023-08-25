import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://org.okta.com  ->  gives the URL to the application
    # --force                     ->  overrides a threadcount >1, since ratelimiting
    #
    if 'url' in pluginargs.keys():
        if pluginargs["thread_count"] == 1 or (pluginargs["thread_count"] > 1 and 'force' in pluginargs.keys()):
            if not pluginargs['url'].startswith("https://") and not pluginargs['url'].startswith("http://"):
                pluginargs['url'] = "https://" + pluginargs['url']
            return True, None, pluginargs
        else:
            error = "WARNING, threadcount > 1 will likely result in ratelimiting from Okta, to override add a --force flag"
            return False, error, None
    else:
        error = "Missing url argument, specify as --url https://org.okta.com or --url org.okta.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    resp = requests.get(api_dict['proxy_url'], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuing"

    return success, output, pluginargs
