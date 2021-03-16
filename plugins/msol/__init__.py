import requests

def validate(pluginargs, args):
    pluginargs = {'url' : "https://login.microsoft.com"}
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
