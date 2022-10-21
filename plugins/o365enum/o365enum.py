import requests
import utils.utils as utils

def o365enum_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result': None,    # Can be "success", "failure" or "potential"
		'error' : False,
        'output' : ""
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()


    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:

        # some code stolen from:
        # https://github.com/BarrelTit0r/o365enum/blob/master/o365enum.py
        # https://github.com/dievus/Oh365UserFinder/blob/main/oh365userfinder.py

        if_exists_result_codes = {"-1": "UNKNOWN_ERROR", "0": "VALID_USERNAME", "1": "UNKNOWN_USERNAME", "2": "THROTTLE", "4": "ERROR", "5": "VALID_USERNAME_DIFFERENT_IDP", "6": "VALID_USERNAME"}
        domainType = {"1": "UNKNOWN", "2": "COMMERCIAL", "3": "MANAGED", "4": "FEDERATED", "5": "CLOUD_FEDERATED"}

        body = '{"Username":"%s"}' % username

        sess = requests.session()

        response = sess.post("{}/common/GetCredentialType".format(url), headers=headers, data=body)

        throttle_status = int(response.json()['ThrottleStatus'])
        if_exists_result = str(response.json()['IfExistsResult'])
        if_exists_result_response = if_exists_result_codes[if_exists_result]
        domain_type = domainType[str(response.json()['EstsProperties']['DomainType'])]
        domain = username.split("@")[1]

        if domain_type != "MANAGED":
            data_response["result"] = "failure"
            data_response['output'] = "[-] FAILURE: {username} Domain type {domaintype} not supported for user enum".format(username=username,domaintype=domain_type)

        elif throttle_status != 0 or if_exists_result_response == "THROTTLE":
            data_response['output'] = "[?] WARNING: Throttle detected on user {}".format(username=username)
            data_response['result'] = "failure"

        else:
            sign = "[-]"
            data_response["result"] = "failure"
            if "VALID_USER" in if_exists_result_response:
                sign = "[!]"
                data_response["result"] = "success"
            data_response['output'] = "{sign} {if_exists_result_response}: {username}".format(sign=sign, if_exists_result_response=if_exists_result_response, username=username)

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
