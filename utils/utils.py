import random, requests, json
from utils.ntlmdecode import ntlmdecode
from datetime import datetime

# We can set anything up here for easy parsing and access later, for the moment this only houses the slack webhook, can probably add discord and other platforms at a later date as parsing isn't an issue.

def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def generate_string(chars):

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(chars))


def add_custom_headers(pluginargs, headers):

    if "custom-headers" in pluginargs.keys():
        for header in pluginargs["custom-headers"]:
            headers[header] = pluginargs["custom-headers"][header]

    return headers


def get_owa_domain(url, uri, useragent):
    # Stolen from https://github.com/byt3bl33d3r/SprayingToolkit who stole it from https://github.com/dafthack/MailSniper
    auth_header = {
        "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : generate_ip(),
        "x-amzn-apigateway-api-id" : generate_id(),
        "X-My-X-Amzn-Trace-Id" : generate_trace_id(),
    }

    r = requests.post(f"{url}{uri}", headers=auth_header, verify=False)
    if r.status_code == 401:
        ntlm_info = ntlmdecode(r.headers["x-amzn-Remapped-WWW-Authenticate"])
        return ntlm_info["NetBIOS_Domain_Name"]
    else:
        return "NOTFOUND"


# Colour Functions - ZephrFish
def prRed(skk):
    return f"\033[91m{skk}\033[00m" 

def prGreen(skk):
    return f"\033[92m{skk}\033[00m"

def prYellow(skk):
    return f"\033[93m{skk}\033[00m"
