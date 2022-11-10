import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def o365enum_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
		'error' : False,
        'output' : "",
        'valid_user' : False
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()


    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        # some code stolen from:
        # https://github.com/BarrelTit0r/o365enum/blob/master/o365enum.py
        # https://github.com/dievus/Oh365UserFinder/blob/main/oh365userfinder.py

        if_exists_result_codes = {
            "-1" : "UNKNOWN_ERROR",
            "0" : "VALID_USERNAME",
            "1" : "UNKNOWN_USERNAME",
            "2" : "THROTTLE",
            "4" : "ERROR",
            "5" : "VALID_USERNAME_DIFFERENT_IDP",
            "6" : "VALID_USERNAME"
        }

        domainType = {
            "1" : "UNKNOWN",
            "2" : "COMMERCIAL",
            "3" : "MANAGED",
            "4" : "FEDERATED",
            "5" : "CLOUD_FEDERATED"
        }

        body = '{"Username":"%s"}' % username

        sess = requests.session()

        response = sess.post(f"{url}/common/GetCredentialType", headers=headers, data=body)

        throttle_status = int(response.json()['ThrottleStatus'])
        if_exists_result = str(response.json()['IfExistsResult'])
        if_exists_result_response = if_exists_result_codes[if_exists_result]
        domain_type = domainType[str(response.json()['EstsProperties']['DomainType'])]
        domain = username.split("@")[1]

        if domain_type != "MANAGED":
            data_response["result"] = "failure"
            data_response['output'] = f"[-] FAILURE: {username} Domain type {domain_type} not supported for user enum"

        elif throttle_status != 0 or if_exists_result_response == "THROTTLE":
            data_response['output'] = f"[?] WARNING: Throttle detected on user {username}"
            data_response['result'] = "failure"

        else:
            sign = "[-]"
            data_response["result"] = "failure"
            if "VALID_USER" in if_exists_result_response:
                sign = "[!]"
                data_response["result"] = "success"
                data_response['valid_user'] = True
            data_response['output'] = f"{sign} {if_exists_result_response}: {username}"

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
