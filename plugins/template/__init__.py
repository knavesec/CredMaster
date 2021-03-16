import requests

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


def testconnect(pluginargs, args, api_dict):

    success = True
    resp = requests.get(api_dict['proxy_url'])

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuting"

    return success, output, pluginargs
