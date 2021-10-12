import datetime, requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def template_authenticate(url, username, password, useragent, pluginargs): # CHANGEME: replace template with plugin name

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # not all of these are used, provided for future dev if needed
    # Only ones necessary to return at the moment are:
    # error
    # output
    # success
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

    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    # CHANGEME: Add more if necessary
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    try:

        resp = requests.post("{}/uri".format(url),headers=headers)

        if Success:
            data_response['success'] = True
            data_response['output'] = 'SUCCESS_MESSAGE: => {}:{}'.format(username, password)

        elif Success_but_2fa:
            data_response['success'] = True
            data_response['output'] = 'SUCCESS_2FA_MESSAGE: => {}:{}'.format(username, password)
            data_response['2fa_enabled'] = True

        elif lockout_or_pwd_expired_or_other:
            data_response['success'] = False
            data_response['output'] = 'ISSUE_MESSAGE: {} => {}:{}'.format(resp.status_code, username, password)

        else: #fail
            data_response['success'] = False
            data_response['output'] = 'FAILURE_MESSAGE: {} => {}:{}'.format(resp.status_code, username, password)
            data_response['2fa_enabled'] = True

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex

    return data_response
