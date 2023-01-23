import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def gmailenum_authenticate(url, username, password, useragent, pluginargs):

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
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = requests.get(f"{url}/mail/gxlu",params={"email":username},headers=headers)

        if "Set-Cookie" in resp.headers.keys():
            data_response['result'] = "success"
            data_response['output'] = f"[!] VALID_USERNAME: {username} - Status: {resp.status_code}"
            data_response['valid_user'] = True

        else:
            data_response['result'] = "failure"
            data_response['output'] = f"[-] UNKNOWN_USERNAME: {username} - Status: {resp.status_code}"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
