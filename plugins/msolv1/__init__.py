import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    if pluginargs:
        if 'random_client' in pluginargs:
            pluginargs['random_client'] = True
        if 'use_agent' in pluginargs:
            pluginargs['use_agent'] = True
        if 'response_log' in pluginargs:
            if not pluginargs['response_log'] or len(pluginargs['response_log']) < 1:
                return False, 'Provide a filename for the "response_log" parameter', pluginargs
        if 'tenant_id' in pluginargs:
            if not pluginargs['tenant_id'] or len(pluginargs['tenant_id']) < 1:
                return False, 'Provide a GUID value for the "tenant_id" parameter', pluginargs
        pluginargs['url'] = 'https://login.microsoft.com'
    else:
        pluginargs = {'url' : "https://login.microsoft.com"}
    return True, None, pluginargs


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

    try:
        resp = requests.get(api_dict['proxy_url'], headers=headers)

        if resp.status_code == 504:
            output = "Testconnect: Connection failed, endpoint timed out, exiting"
            success = False
        else:
            output = "Testconnect: Connection success, continuing"
    except Exception as e:
        output = f"Error in connection, will exit. Error: {str(e)}"
        success = False

    return success, output, pluginargs
