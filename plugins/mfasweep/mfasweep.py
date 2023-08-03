import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def mfasweep_authenticate(api_dict, username, password, useragent, pluginargs): # CHANGEME: replace template with plugin name

    url = api_dict["proxy_url"]

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

        if api_dict["original_url"] == "https://login.microsoftonline.com":
            data_response['result'], data_response['output'] = test_login_microsoftonline_com(api_dict, username, password, useragent, pluginargs, headers)

        elif api_dict["original_url"] == "https://passwordreset.microsoftonline.com":
            data_response['result'], data_response['output'] = test_passwordreset_microsoftonline_com(api_dict, username, password, useragent, pluginargs, headers)

        else: 
            data_response['result'] = "failure"
            data_response['output'] = f"[-] UNKNOWN_URL: {api_dict['original_url']}"
        




    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response



def test_login_microsoftonline_com(api_dict, username, password, useragent, pluginargs, headers):
    
    output = "Tested login.microsoftonline.com"
    result = "success"

    return result, output



def test_passwordreset_microsoftonline_com(api_dict, username, password, useragent, pluginargs, headers):
    
    output = "Tested passwordreset.microsoftonline.com"
    result = "failure"

    return result, output
