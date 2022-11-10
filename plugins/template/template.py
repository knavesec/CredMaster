import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def template_authenticate(url, username, password, useragent, pluginargs): # CHANGEME: replace template with plugin name

    # not all of these are used, provided for future dev if needed
    # Only ones necessary to return at the moment are:
    # error
    # output
    # success
    # valid_user
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

        resp = requests.post(f"{url}/uri",headers=headers)

        if Success:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: => {username}:{password}"
            data_response['valid_user'] = True

        elif Success_but_2fa:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: 2FA Required => {username}:{password}"
            data_response['valid_user'] = True

        elif lockout_or_pwd_expired_or_other:
            data_response['result'] = "potential"
            data_response['output'] = f"[*] POTENTIAL: {resp.status_code} => {username}:{password}"

        elif assorted_issue:
            data_response['result'] = "potential"
            data_response['output'] = f"[?] WARNING: issue_description {resp.status_code} => {username}:{password}"

        elif valid_user:
            data_response['result'] = "failure"
            data_response['output'] = f"[!] VALID_USERNAME: {resp.status_code} => {username}:{password}"
            data_response['valid_user'] = True

        else: #fail
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE: {resp.status_code} => {username}:{password}"

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
