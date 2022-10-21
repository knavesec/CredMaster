import requests
import utils.utils as utils

def template_authenticate(url, username, password, useragent, pluginargs): # CHANGEME: replace template with plugin name

    # not all of these are used, provided for future dev if needed
    # Only ones necessary to return at the moment are:
    # error
    # output
    # success
    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
		'error' : False,
        'output' : ""
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    # CHANGEME: Add more if necessary
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = requests.post("{}/uri".format(url),headers=headers)

        if Success:
            data_response['success'] = "success"
            data_response['output'] = '[+] SUCCESS: => {}:{}'.format(username, password)

        elif Success_but_2fa:
            data_response['success'] = "success"
            data_response['output'] = '[+] SUCCESS: 2FA Required => {}:{}'.format(username, password)

        elif lockout_or_pwd_expired_or_other:
            data_response['success'] = "potential"
            data_response['output'] = '[*] POTENTIAL: {} => {}:{}'.format(resp.status_code, username, password)

        elif assorted_issue:
            data_response['success'] = "potential"
            data_response['output'] = '[?] WARNING: issue_description {} => {}:{}'.format(resp.status_code, username, password)

        elif valid_user:
            data_response['success'] = "failure"
            data_response['output'] = '[!] VALID_USERNAME: {} => {}:{}'.format(resp.status_code, username, password)

        else: #fail
            data_response['success'] = "failure"
            data_response['output'] = '[-] FAILURE: {} => {}:{}'.format(resp.status_code, username, password)

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
