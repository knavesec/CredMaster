import datetime, requests
import re
from utils.utils import generate_ip, generate_id, generate_trace_id


def o365enum_authenticate(url, username, password, useragent, pluginargs): 

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


    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    try:
        body = '{"Username":"%s"}' % username
        accountQuery = requests.post("https://login.microsoftonline.com/common/GetCredentialType",data=body)
        accountQuery_response = accountQuery.text
        valid_response = re.search('"IfExistsResult":0,', accountQuery_response)
        valid_response5 = re.search('"IfExistsResult":5,', accountQuery_response)
        valid_response6 = re.search('"IfExistsResult":6,', accountQuery_response)
        invalid_response = re.search('"IfExistsResult":1,', accountQuery_response)
        #print(accountQuery.text)
        if invalid_response:
            data_response['output'] = "The user {username} doesn't exist.".format(username=username)
            data_response['success'] = False
        elif valid_response or valid_response5 or valid_response6:
            data_response['output'] = "Username: {username} could exist.".format(username=username)
            data_response['success'] = False
        else: #fail
            data_response['success'] = False
            data_response['output'] = 'FAILURE_MESSAGE: {} => {}:{}'.format(resp.status_code, username, password)
            data_response['2fa_enabled'] = True

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
