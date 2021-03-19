import requests

def validate(pluginargs, args):

    #
    # Plugin Args
    #
    # --url https://domain.com    ->  gives the URL to the application
    # --domain DOMAIN              ->  Input domain name
    #

    if 'url' in pluginargs.keys():
        if "https://" not in pluginargs['url'] and "http://" not in pluginargs['url']:
            error = "URL requires http:// or https:// prefix"
            return False, error, None
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://domain.com"
        return False, error, None

    if 'domain' in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing domain argument, specify as --domain ACME"
        return False, error, None

def testconnect(pluginargs, args, api_dict):

    success = True
    resp = requests.get(api_dict['proxy_url'] + "/owa/auth/logon.aspx")

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    elif "OwaPage" in resp.text:
        output = "Testconnect: Verified OWA instance, connected"
    else:
        output = "Testconnect: Warning, OWA instance not indicated, continuting"

    return success, output, pluginargs
