import requests, random

def validate(pluginargs, args):
    pluginargs = {'url' : "https://login.microsoft.com"}
    return True, None, pluginargs


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    resp = requests.get(api_dict['proxy_url'], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuting"

    return success, output, pluginargs


def generate_ip():
    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():
    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second
