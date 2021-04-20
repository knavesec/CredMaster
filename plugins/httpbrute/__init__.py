import requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --auth basic/digest/ntlm     ->  method of authentication
    # --url https://org.okta.com   ->  gives the URL to the application
    #
    auth_methods = ["basic", "ntlm", "digest"]
    if 'url' in pluginargs.keys() and 'auth' in pluginargs.keys():

        if pluginargs['auth'].lower() not in auth_methods:
            error = "Auth method must be basic, digest or ntlm"
            return False, error, None
        pluginargs['auth'] = pluginargs['auth'].lower()
        full_url = pluginargs['url']
        pluginargs['url'] = '/'.join(full_url.split('/')[:3])
        pluginargs['uri'] = '/'.join(full_url.split('/')[3:])
        return True, None, pluginargs
    else:
        error = "Missing url or auth method, specify as --url https://target.com/endpoint/to/test.ext or --auth basic"
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
