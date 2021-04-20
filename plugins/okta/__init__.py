import requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://org.okta.com  ->  gives the URL to the application
    # --force                     ->  overrides a threadcount >1, since ratelimiting
    #
    if 'url' in pluginargs.keys():
        if args.threads == 1 or (args.threads > 1 and 'force' in pluginargs.keys()):
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
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    resp = requests.get(api_dict['proxy_url'], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuting"

    return success, output, pluginargs
