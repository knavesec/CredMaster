import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --input1          ->  input 1 docs
    # --input2          ->  input 2 docs
    # ...

    #
    # pluginargs = {
    #    'url' = 'static_url or pluginarg_input_url' - REQUIRED
    #    'other_arg' = ....
    # }

    # Return Args
    # Bool - T/F if all plugin args are set
    # Str/None - Error message, if there are any
    # Dict - Plugin args returned, 'url' arg required
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

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuing"

    return success, output, pluginargs
