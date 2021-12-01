import requests
import re
from utils.utils import generate_ip, generate_id, generate_trace_id
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    pluginargs['url'] = "https://autodiscover-s.outlook.com"
    if 'domain' in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing domain argument, specify as --domain domain.com"
        return False, error, None
    

def testconnect(pluginargs, args, api_dict, useragent):
    domain_name = pluginargs['domain']
    success = True
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    resp = requests.get("https://login.microsoftonline.com/common/GetCredentialType", headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        url=(f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain_name}")
        print(url)
        req = requests.get(url)
        response = req.text
        valid_response = re.search('"NameSpaceType":"Managed",', response)
        if valid_response:
             output = "Testconnect: Connection success, tennant is using a managed instance, continuting."
        else:
    	     output = "Testconnect: Connection failed, tennant not using a managed instance, exiting"
    	     success = False

    return success, output, pluginargs
