import requests

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


def testconnect(pluginargs, args, api_dict):

    success = True
    resp = requests.get(api_dict['proxy_url'] + "/remote/login?lang=en")

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    elif "fortinet" in resp.text:
        output = "Testconnect: Verified Fortinet instance, connected"
    else:
        output = "Testconnect: Warning, Fortinet client not indicated, continuting"

    return success, output, pluginargs
